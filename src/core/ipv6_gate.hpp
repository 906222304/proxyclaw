#pragma once

// IPv6 block for proxied processes (ROADMAP v0.14 #5).
//
// ProxyClaw does not proxy IPv6 yet. A proxied process that reaches a
// dual-stack host over IPv6 would therefore leave direct, past the proxy.
// With `ipv6.mode = block` (the default) such a flow is refused instead:
//   - TCP: the SOCKET layer decides block / allow for the IPv6 CONNECT and
//     stores it here per local port; the IPv6 NETWORK worker answers a
//     blocked SYN with a TCP RST, so connect() fails at once and the
//     application (Happy Eyeballs, getaddrinfo order) moves on to IPv4,
//     which is proxied as usual.
//   - UDP: datagrams from a proxied port to an IPv6 destination are dropped
//     (windivert_network_udp.hpp); QUIC falls back to TCP.
// Local-scope IPv6 (link-local, unique local, multicast) is never blocked.
//
// This header holds only bookkeeping and packet building (no WinDivert), so
// it is unit tested on its own. Packet is whatever the caller re-sends.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#include "udp/udp_first_packet.hpp"

namespace clew {

enum class v6_verdict : uint8_t {
    none,    // no decision for this port (yet)
    allow,   // send it (not proxied, excluded, mode = direct)
    block,   // proxied process: refuse so it falls back to IPv4
};

template <typename Packet, typename Clock = std::chrono::steady_clock>
class ipv6_tcp_gate {
public:
    using time_point = typename Clock::time_point;
    using duration   = typename Clock::duration;

    // ttl: how long a CONNECT's verdict covers SYNs from its port. A SYN
    // later than that (a retransmit of an allowed flow, or a new flow whose
    // CLOSE we missed) waits for a fresh verdict like an unknown port.
    explicit ipv6_tcp_gate(duration ttl = std::chrono::seconds{2},
                           UdpParkingLimits limits = {256, 8})
        : ttl_(ttl), parker_(limits) {}

    // SOCKET strand: store the verdict for `port` and hand back the SYNs
    // parked for it, in arrival order. The caller acts on them.
    std::vector<Packet> decide(uint16_t port, v6_verdict v, time_point now) {
        {
            std::lock_guard lock(mu_);
            slots_[port] = slot{v, now};
        }
        return parker_.take(port);
    }

    // SOCKET strand, on CLOSE: forget the port. Anything still parked for it
    // is returned (the socket is gone; the caller sends it on, harmlessly).
    std::vector<Packet> clear(uint16_t port) {
        {
            std::lock_guard lock(mu_);
            slots_.erase(port);
        }
        return parker_.take(port);
    }

    // NETWORK worker: the verdict for a SYN from `port`, or none.
    v6_verdict lookup(uint16_t port, time_point now) const {
        std::lock_guard lock(mu_);
        return lookup_locked(port, now);
    }

    // NETWORK worker: park a SYN that has no verdict. Returns decided when a
    // verdict landed meanwhile (look it up again and act on it), full when
    // over a limit (send it on).
    udp_park_result park(uint16_t port, Packet& packet, time_point now) {
        return parker_.park(port, packet, now, [&] {
            std::lock_guard lock(mu_);
            return lookup_locked(port, now) == v6_verdict::none;
        });
    }

    // Watchdog: SYNs whose verdict did not arrive within `deadline`.
    std::vector<std::pair<uint16_t, std::vector<Packet>>> expire(time_point now, duration deadline) {
        return parker_.expire(now, deadline);
    }

    std::size_t parked() const { return parker_.size(); }

private:
    struct slot {
        v6_verdict v = v6_verdict::none;
        time_point at{};
    };

    v6_verdict lookup_locked(uint16_t port, time_point now) const {
        const auto it = slots_.find(port);
        if (it == slots_.end()) return v6_verdict::none;
        if (now - it->second.at > ttl_) return v6_verdict::none;
        return it->second.v;
    }

    duration ttl_;
    mutable std::mutex mu_;
    std::unordered_map<uint16_t, slot> slots_;
    udp_first_packet_parker<Packet, Clock> parker_;
};

// ---- TCP RST for a refused IPv6 SYN ----------------------------------------

inline constexpr std::size_t IPV6_HDR_LEN   = 40;
inline constexpr std::size_t TCP_HDR_LEN    = 20;
inline constexpr std::size_t IPV6_RST_LEN   = IPV6_HDR_LEN + TCP_HDR_LEN;
inline constexpr uint8_t     IPPROTO_TCP_NH = 6;

inline uint16_t ipv6_tcp_checksum(const uint8_t* pkt, std::size_t tcp_len) noexcept {
    uint32_t sum = 0;
    const auto add16 = [&sum](const uint8_t* p, std::size_t n) {
        for (std::size_t i = 0; i + 1 < n; i += 2) sum += (uint32_t(p[i]) << 8) | p[i + 1];
        if (n & 1) sum += uint32_t(p[n - 1]) << 8;
    };
    add16(pkt + 8, 32);                         // source + destination address
    sum += static_cast<uint32_t>(tcp_len);      // upper-layer length
    sum += IPPROTO_TCP_NH;                      // next header
    add16(pkt + IPV6_HDR_LEN, tcp_len);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xffff);
}

// Build the RST|ACK that answers an outbound IPv6 TCP SYN, addressed back to
// the application (inject it inbound). `syn` must be a plain IPv6 header
// followed directly by TCP (no extension headers). Returns the length
// written to `out` (IPV6_RST_LEN), or 0 if `syn` is not such a SYN.
inline std::size_t build_ipv6_tcp_rst(const uint8_t* syn, std::size_t len,
                                      uint8_t (&out)[IPV6_RST_LEN]) noexcept {
    if (len < IPV6_RST_LEN || (syn[0] >> 4) != 6 || syn[6] != IPPROTO_TCP_NH) return 0;
    const uint8_t* tcp = syn + IPV6_HDR_LEN;
    const uint8_t flags = tcp[13];
    if (!(flags & 0x02) || (flags & 0x10)) return 0;   // SYN without ACK only

    std::memset(out, 0, sizeof(out));
    out[0] = 0x60;                       // version 6, no traffic class / flow label
    out[4] = 0;
    out[5] = static_cast<uint8_t>(TCP_HDR_LEN);
    out[6] = IPPROTO_TCP_NH;
    out[7] = 64;                         // hop limit
    std::memcpy(out + 8, syn + 24, 16);  // source = the SYN's destination
    std::memcpy(out + 24, syn + 8, 16);  // destination = the application

    uint8_t* t = out + IPV6_HDR_LEN;
    t[0] = tcp[2]; t[1] = tcp[3];        // source port = SYN destination port
    t[2] = tcp[0]; t[3] = tcp[1];        // destination port = application port
    // seq 0; ack = SYN seq + 1
    const uint32_t seq = (uint32_t(tcp[4]) << 24) | (uint32_t(tcp[5]) << 16) |
                         (uint32_t(tcp[6]) << 8) | tcp[7];
    const uint32_t ack = seq + 1;
    t[8]  = static_cast<uint8_t>(ack >> 24);
    t[9]  = static_cast<uint8_t>(ack >> 16);
    t[10] = static_cast<uint8_t>(ack >> 8);
    t[11] = static_cast<uint8_t>(ack);
    t[12] = 0x50;                        // data offset 5 words
    t[13] = 0x14;                        // RST | ACK
    const uint16_t ck = ipv6_tcp_checksum(out, TCP_HDR_LEN);
    t[16] = static_cast<uint8_t>(ck >> 8);
    t[17] = static_cast<uint8_t>(ck);
    return IPV6_RST_LEN;
}

} // namespace clew
