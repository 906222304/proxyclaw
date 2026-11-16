#pragma once

// IPv6 TCP flows handed to the local acceptor (ipv6.mode = proxy).
//
// The IPv4 path keeps its NAT state in PortTracker: a lock-free 64-byte slot
// per local port, which has no room for two 16-byte addresses. IPv6 traffic
// is a fraction of IPv4 and only proxied ports ever reach the locked part,
// so this table is simpler: a per-port atomic flag answers "is this port
// ours?" for every diverted packet without a lock, and the flow itself
// (original remote, group, the application's own address and interface) sits
// in a mutex-guarded map.
//
// Lifecycle of a port:
//   publish   SOCKET strand, an IPv6 CONNECT decided `proxy`. Replaces any
//             older flow on the port (a new CONNECT is a new connection).
//   erase     SOCKET strand, an IPv6 CONNECT decided allow / block: a later
//             direct connection on a recycled port must never be reflected.
//   take      relay, once per accepted connection: the flow it serves.
//   retire    relay end: the flow keeps translating FIN / ACK and
//             retransmissions for `drain` and then disappears.
// The NETWORK worker reads (`find`) and records the application's address
// and interface from the first reflected SYN (`remember_route`).
//
// Pure bookkeeping (no WinDivert), unit tested in tests/test_ipv6_gate.cpp.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace clew {

struct v6_flow {
    std::array<uint8_t, 16> remote{};   // original destination, network order
    uint16_t remote_port = 0;           // host order
    uint32_t group_id    = 0;
    uint64_t id          = 0;           // set by publish(); retire() matches it
    // Learned from the first reflected SYN, needed to restore replies.
    std::array<uint8_t, 16> local{};
    uint32_t if_idx      = 0;
    uint32_t sub_if_idx  = 0;
    bool     has_route   = false;
};

template <typename Clock = std::chrono::steady_clock>
class ipv6_flow_table {
public:
    using time_point = typename Clock::time_point;
    using duration   = typename Clock::duration;

    explicit ipv6_flow_table(duration drain = std::chrono::seconds{10})
        : drain_(drain), active_(std::make_unique<std::atomic<uint8_t>[]>(65536)) {
        for (std::size_t i = 0; i < 65536; ++i) active_[i].store(0, std::memory_order_relaxed);
    }

    uint64_t publish(uint16_t port, v6_flow flow) {
        std::lock_guard lock(mu_);
        flow.id = ++next_id_;
        flow.has_route = false;
        flows_[port] = slot{flow, false, {}};
        active_[port].store(1, std::memory_order_release);
        return flow.id;
    }

    void erase(uint16_t port) {
        if (!active_[port].load(std::memory_order_acquire)) return;
        std::lock_guard lock(mu_);
        flows_.erase(port);
        active_[port].store(0, std::memory_order_release);
    }

    // Lock-free pre-check for every diverted packet.
    bool maybe_ours(uint16_t port) const noexcept {
        return active_[port].load(std::memory_order_acquire) != 0;
    }

    // The flow translating packets on `port`: live, or draining and not yet
    // expired. Expired entries are removed on the way.
    std::optional<v6_flow> find(uint16_t port, time_point now) {
        if (!maybe_ours(port)) return std::nullopt;
        std::lock_guard lock(mu_);
        const auto it = flows_.find(port);
        if (it == flows_.end()) return std::nullopt;
        if (it->second.draining && now >= it->second.drain_until) {
            flows_.erase(it);
            active_[port].store(0, std::memory_order_release);
            return std::nullopt;
        }
        return it->second.flow;
    }

    // The relay's flow: only a live (not draining) one.
    std::optional<v6_flow> take(uint16_t port) {
        if (!maybe_ours(port)) return std::nullopt;
        std::lock_guard lock(mu_);
        const auto it = flows_.find(port);
        if (it == flows_.end() || it->second.draining) return std::nullopt;
        return it->second.flow;
    }

    void remember_route(uint16_t port, const uint8_t local[16],
                        uint32_t if_idx, uint32_t sub_if_idx) {
        std::lock_guard lock(mu_);
        const auto it = flows_.find(port);
        if (it == flows_.end()) return;
        auto& f = it->second.flow;
        std::copy(local, local + 16, f.local.begin());
        f.if_idx = if_idx;
        f.sub_if_idx = sub_if_idx;
        f.has_route = true;
    }

    // Relay end. A newer flow on the port (different id) is left alone.
    void retire(uint16_t port, uint64_t id, time_point now) {
        std::lock_guard lock(mu_);
        const auto it = flows_.find(port);
        if (it == flows_.end() || it->second.flow.id != id) return;
        it->second.draining = true;
        it->second.drain_until = now + drain_;
    }

    std::size_t size() const {
        std::lock_guard lock(mu_);
        return flows_.size();
    }

private:
    struct slot {
        v6_flow    flow;
        bool       draining = false;
        time_point drain_until{};
    };

    duration drain_;
    std::unique_ptr<std::atomic<uint8_t>[]> active_;
    mutable std::mutex mu_;
    std::unordered_map<uint16_t, slot> flows_;
    uint64_t next_id_ = 0;
};

} // namespace clew
