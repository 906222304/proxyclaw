// UDP per-packet addressing primitives (src/udp/udp_flow.hpp) and the SOCKS5
// UDP codec round trip that carries each datagram's own destination.
// No driver, no admin rights.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "udp/socks5_udp_codec.hpp"
#include "udp/udp_flow.hpp"

using namespace clew;
using namespace std::chrono_literals;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    // network byte order, as read from an IP header
    uint32_t v{};
    auto* p = reinterpret_cast<uint8_t*>(&v);
    p[0] = a; p[1] = b; p[2] = c; p[3] = d;
    return v;
}

void peers_track_address_and_port() {
    UdpPeerSet peers;
    peers.add(ip(1, 1, 1, 1), 53);
    peers.add(ip(8, 8, 8, 8), 53);
    check(peers.contains(ip(1, 1, 1, 1), 53), "first peer kept");
    check(peers.contains(ip(8, 8, 8, 8), 53), "second peer kept (no overwrite)");
    check(!peers.contains(ip(1, 1, 1, 1), 54), "same address, other port is not a peer");
    check(!peers.contains(ip(9, 9, 9, 9), 53), "unknown address is not a peer");
    peers.add(ip(1, 1, 1, 1), 53);
    check(peers.size() == 2, "re-adding a peer does not grow the set");
}

void peers_evict_least_recently_used() {
    UdpPeerSet peers(2);
    auto t0 = UdpPeerSet::clock::now();
    check(!peers.add(ip(10, 0, 0, 1), 1, t0), "no eviction below capacity");
    check(!peers.add(ip(10, 0, 0, 2), 2, t0 + 1s), "no eviction at capacity");
    peers.add(ip(10, 0, 0, 1), 1, t0 + 2s);  // refresh the first
    check(peers.add(ip(10, 0, 0, 3), 3, t0 + 3s), "eviction reported when full");
    check(peers.contains(ip(10, 0, 0, 1), 1), "recently used peer survives");
    check(!peers.contains(ip(10, 0, 0, 2), 2), "least recently used peer evicted");
    check(peers.contains(ip(10, 0, 0, 3), 3), "new peer added");
}

void codec_keeps_each_destination() {
    const std::vector<uint8_t> payload{0xde, 0xad, 0xbe, 0xef};
    struct Case { uint32_t addr; uint16_t port; };
    for (auto c : {Case{ip(1, 1, 1, 1), 53}, Case{ip(8, 8, 4, 4), 443}, Case{ip(203, 0, 113, 9), 65535}}) {
        auto frame = socks5_udp::encode(c.addr, c.port, payload.data(), payload.size());
        auto decoded = socks5_udp::decode(frame.data(), frame.size());
        check(decoded.has_value(), "frame decodes");
        if (!decoded) continue;
        check(decoded->addr_net == c.addr, "address round trips");
        check(decoded->port_host == c.port, "port round trips");
        check(decoded->data_len == payload.size() &&
              std::equal(payload.begin(), payload.end(), decoded->data), "payload round trips");
    }
    std::vector<uint8_t> fragmented{0, 0, 1, 1, 1, 1, 1, 1, 0, 53, 0xaa};
    check(!socks5_udp::decode(fragmented.data(), fragmented.size()), "fragmented frame rejected");
}

std::array<uint8_t, 16> v6(uint16_t last) {
    // 2001:db8::<last>
    std::array<uint8_t, 16> a{0x20, 0x01, 0x0d, 0xb8};
    a[14] = static_cast<uint8_t>(last >> 8);
    a[15] = static_cast<uint8_t>(last & 0xFF);
    return a;
}

void peers_keep_families_apart() {
    UdpPeerSet peers;
    const auto a = v6(1), b = v6(2);
    peers.add6(a.data(), 53);
    check(peers.contains6(a.data(), 53), "IPv6 peer kept");
    check(!peers.contains6(a.data(), 54), "IPv6 same address, other port is not a peer");
    check(!peers.contains6(b.data(), 53), "other IPv6 address is not a peer");
    // An IPv6 address whose first four bytes equal an IPv4 peer stays apart.
    std::array<uint8_t, 16> lookalike{1, 1, 1, 1};
    peers.add(ip(1, 1, 1, 1), 53);
    check(!peers.contains6(lookalike.data(), 53), "IPv4 peer does not match an IPv6 lookalike");
    peers.add6(lookalike.data(), 53);
    check(peers.size() == 3, "IPv4 and IPv6 lookalike are two peers");
    check(peers.contains(ip(1, 1, 1, 1), 53), "IPv4 peer kept beside IPv6");

    UdpPeerSet small(1);
    small.add(ip(10, 0, 0, 1), 1);
    check(small.add6(a.data(), 1), "eviction across families reported");
    check(!small.contains(ip(10, 0, 0, 1), 1) && small.contains6(a.data(), 1), "LRU across families");
}

void codec_ipv6_round_trip() {
    const std::vector<uint8_t> payload{1, 2, 3};
    const auto a = v6(0xabcd);
    auto frame = socks5_udp::encode6(a.data(), 5353, payload.data(), payload.size());
    check(frame.size() == 22 + payload.size(), "ATYP 4 frame size");
    check(frame[3] == 0x04, "ATYP 4");
    auto d = socks5_udp::decode(frame.data(), frame.size());
    check(d.has_value() && d->v6, "IPv6 frame decodes as IPv6");
    if (d) {
        check(d->addr6 == a, "IPv6 address round trips");
        check(d->port_host == 5353, "IPv6 port round trips");
        check(d->data_len == payload.size() &&
              std::equal(payload.begin(), payload.end(), d->data), "IPv6 payload round trips");
    }
    auto empty = socks5_udp::encode6(a.data(), 1, nullptr, 0);
    auto de = socks5_udp::decode(empty.data(), empty.size());
    check(de.has_value() && de->data_len == 0, "empty IPv6 datagram decodes");
    std::vector<uint8_t> short_v6(frame.begin(), frame.begin() + 21);
    check(!socks5_udp::decode(short_v6.data(), short_v6.size()), "truncated ATYP 4 frame rejected");
    auto v4 = socks5_udp::encode(ip(1, 1, 1, 1), 53, payload.data(), payload.size());
    auto d4 = socks5_udp::decode(v4.data(), v4.size());
    check(d4.has_value() && !d4->v6, "IPv4 frame is not IPv6");
}

void queue_limits_are_sane() {
    UdpQueueLimits l;
    check(l.max_port_packets > 0 && l.max_port_packets < l.max_total_packets, "per-port limit below total");
    check(l.max_total_bytes >= 65535 * 64, "byte limit fits at least 64 max-size datagrams");
}

} // namespace

int main() {
    peers_track_address_and_port();
    peers_evict_least_recently_used();
    codec_keeps_each_destination();
    peers_keep_families_apart();
    codec_ipv6_round_trip();
    queue_limits_are_sane();
    if (failures) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "udp_flow_tests: all passed\n";
    return 0;
}
