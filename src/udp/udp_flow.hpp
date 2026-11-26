#pragma once

// Per-packet UDP addressing primitives shared by the UDP NETWORK layer and the
// relay. Pure C++ (no WinDivert / asio) so they can be unit tested.
//
// A hijacked UDP socket may sendto() many destinations. Each datagram carries
// its own destination from the NETWORK layer to the relay (UdpOutbound), and
// the relay remembers which peers the socket has talked to (UdpPeerSet) so a
// reply is injected with its real source and only from a peer the app
// contacted (address-and-port restricted, like a typical NAT).

#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace clew {

// IPv4 (`dst_addr_net`) or IPv6 (`v6` set, `dst_addr6` in network order;
// ipv6.mode = proxy). One app socket may carry both on a dual-stack port.
struct UdpOutbound {
    uint16_t app_port{};        // host byte order
    uint32_t group_id{};
    uint32_t dst_addr_net{};    // network byte order (IPv4)
    uint16_t dst_port_host{};   // host byte order
    bool     v6{false};
    std::array<uint8_t, 16> dst_addr6{};   // network order (IPv6)
    std::vector<uint8_t> payload;
};

// Receiver of hijacked datagrams (the relay). Called from NETWORK worker
// threads; must not block.
class UdpOutboundSink {
public:
    virtual bool submit(UdpOutbound&& datagram) = 0;
protected:
    ~UdpOutboundSink() = default;
};

class UdpPeerSet {
public:
    using clock = std::chrono::steady_clock;

    explicit UdpPeerSet(size_t capacity = 1024) : capacity_(capacity ? capacity : 1) {}

    // Records (or refreshes) a peer. When full, the least recently used peer
    // is forgotten; returns true when that happened.
    bool add(uint32_t addr_net, uint16_t port_host, clock::time_point now = clock::now()) {
        return add_key(key(addr_net, port_host), now);
    }
    bool add6(const uint8_t* addr16, uint16_t port_host, clock::time_point now = clock::now()) {
        return add_key(key6(addr16, port_host), now);
    }

    bool contains(uint32_t addr_net, uint16_t port_host) const {
        return peers_.contains(key(addr_net, port_host));
    }
    bool contains6(const uint8_t* addr16, uint16_t port_host) const {
        return peers_.contains(key6(addr16, port_host));
    }

    size_t size() const { return peers_.size(); }

private:
    // family (4/6), address (IPv4 in the first 4 bytes), port.
    struct Key {
        std::array<uint8_t, 16> addr{};
        uint16_t port{};
        uint8_t  family{};
        bool operator==(const Key&) const = default;
    };
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            uint64_t a, b;
            std::memcpy(&a, k.addr.data(), 8);
            std::memcpy(&b, k.addr.data() + 8, 8);
            uint64_t h = a * 0x9E3779B97F4A7C15ull ^ (b + 0x632BE59BD9B4E019ull + (a << 6) + (a >> 2));
            h ^= (static_cast<uint64_t>(k.port) << 8 | k.family) * 0xBF58476D1CE4E5B9ull;
            return static_cast<size_t>(h ^ (h >> 31));
        }
    };

    static Key key(uint32_t addr_net, uint16_t port_host) {
        Key k;
        std::memcpy(k.addr.data(), &addr_net, 4);
        k.port = port_host;
        k.family = 4;
        return k;
    }
    static Key key6(const uint8_t* addr16, uint16_t port_host) {
        Key k;
        std::memcpy(k.addr.data(), addr16, 16);
        k.port = port_host;
        k.family = 6;
        return k;
    }

    bool add_key(const Key& k, clock::time_point now) {
        if (auto it = peers_.find(k); it != peers_.end()) {
            it->second = now;
            return false;
        }
        bool evicted = false;
        if (peers_.size() >= capacity_) {
            auto oldest = peers_.begin();
            for (auto it = peers_.begin(); it != peers_.end(); ++it)
                if (it->second < oldest->second) oldest = it;
            peers_.erase(oldest);
            evicted = true;
        }
        peers_.emplace(k, now);
        return evicted;
    }

    size_t capacity_;
    std::unordered_map<Key, clock::time_point, KeyHash> peers_;
};

// Admission control for datagrams queued between the NETWORK workers and the
// relay strand. Bounded so a flood or a stuck proxy cannot grow memory without
// limit; excess datagrams are dropped (UDP semantics) and counted.
struct UdpQueueLimits {
    size_t max_total_packets = 8192;
    size_t max_total_bytes   = 32u * 1024 * 1024;
    size_t max_port_packets  = 512;   // per app socket, covers proxy handshake time
    size_t max_ports         = 1024;  // distinct local UDP ports tracked concurrently
};

} // namespace clew
