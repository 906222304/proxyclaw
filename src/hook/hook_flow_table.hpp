#pragma once

// Hook mode (interception.mode = "hook"): the original destination of each
// redirected connection, keyed by (family, application source port).
//
// The injected DLL binds the socket first, asks the host, and only then
// connects to the loopback relay port. The host publishes the flow before it
// replies, so by the time the relay accepts, the flow is here. The relay
// takes it exactly once. A flow whose connect never arrives (the application
// gave up, the connect failed) is dropped after kMaxAge, and a newer connect
// from the same port simply replaces it.
//
// Pipe threads publish, relay coroutines take: one mutex, tiny critical
// sections, no strand involvement.

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace clew::hook {

struct flow {
    bool                    ipv6 = false;
    uint32_t                v4_host = 0;    // host byte order
    std::array<uint8_t, 16> v6{};           // network byte order
    uint16_t                port = 0;       // host byte order
    uint32_t                group_id = 0;
    uint32_t                pid = 0;
};

class flow_table {
public:
    using clock = std::chrono::steady_clock;
    static constexpr std::chrono::seconds kMaxAge{30};
    static constexpr std::size_t kPruneAbove = 4096;

    void publish(bool ipv6, uint16_t src_port, const flow& f, clock::time_point now = clock::now()) {
        std::lock_guard lock(mu_);
        if (map_.size() >= kPruneAbove) prune_locked(now);
        map_[key(ipv6, src_port)] = entry{f, now};
        ++published_;
    }

    // The flow for an accepted relay connection, removed. nullopt when none
    // was published or it is older than kMaxAge.
    std::optional<flow> take(bool ipv6, uint16_t src_port, clock::time_point now = clock::now()) {
        std::lock_guard lock(mu_);
        const auto it = map_.find(key(ipv6, src_port));
        if (it == map_.end()) return std::nullopt;
        const entry e = it->second;
        map_.erase(it);
        if (now - e.at > kMaxAge) { ++expired_; return std::nullopt; }
        ++taken_;
        return e.f;
    }

    void prune(clock::time_point now = clock::now()) {
        std::lock_guard lock(mu_);
        prune_locked(now);
    }

    struct counters { uint64_t published, taken, expired; std::size_t pending; };
    counters snapshot() const {
        std::lock_guard lock(mu_);
        return {published_, taken_, expired_, map_.size()};
    }

private:
    struct entry { flow f; clock::time_point at; };

    static uint32_t key(bool ipv6, uint16_t port) { return (ipv6 ? 0x10000u : 0u) | port; }

    void prune_locked(clock::time_point now) {
        for (auto it = map_.begin(); it != map_.end();) {
            if (now - it->second.at > kMaxAge) { it = map_.erase(it); ++expired_; }
            else ++it;
        }
    }

    mutable std::mutex mu_;
    std::unordered_map<uint32_t, entry> map_;
    uint64_t published_{0}, taken_{0}, expired_{0};
};

} // namespace clew::hook
