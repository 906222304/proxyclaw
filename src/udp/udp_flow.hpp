#pragma once

// Per-packet UDP addressing primitives shared by the UDP NETWORK layer and the
// relay. Pure C++ (no WinDivert / asio) so they can be unit tested.
//
// A hijacked UDP socket may sendto() many destinations. Each datagram carries
// its own destination from the NETWORK layer to the relay (UdpOutbound), and
// the relay remembers which peers the socket has talked to (UdpPeerSet) so a
// reply is injected with its real source and only from a peer the app
// contacted (address-and-port restricted, like a typical NAT).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace clew {

struct UdpOutbound {
    uint16_t app_port{};        // host byte order
    uint32_t group_id{};
    uint32_t dst_addr_net{};    // network byte order
    uint16_t dst_port_host{};   // host byte order
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
        const auto k = key(addr_net, port_host);
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

    bool contains(uint32_t addr_net, uint16_t port_host) const {
        return peers_.contains(key(addr_net, port_host));
    }

    size_t size() const { return peers_.size(); }

private:
    static uint64_t key(uint32_t addr_net, uint16_t port_host) {
        return (static_cast<uint64_t>(addr_net) << 16) | port_host;
    }

    size_t capacity_;
    std::unordered_map<uint64_t, clock::time_point> peers_;
};

// Admission control for datagrams queued between the NETWORK workers and the
// relay strand. Bounded so a flood or a stuck proxy cannot grow memory without
// limit; excess datagrams are dropped (UDP semantics) and counted.
struct UdpQueueLimits {
    size_t max_total_packets = 8192;
    size_t max_total_bytes   = 32u * 1024 * 1024;
    size_t max_port_packets  = 512;   // per app socket, covers proxy handshake time
};

} // namespace clew
