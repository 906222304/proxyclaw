#pragma once

// Pure index and lifecycle state for Hook-mode per-flow loopback UDP relays.
// No Windows or Asio headers so unit tests can exercise key hashing, reuse,
// close grace periods, idle expiration, and relay-cap eviction on any OS.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clew::hook {

struct udp_flow_key {
    bool                    ipv6{false};
    uint16_t                app_port{0};    // host byte order
    uint16_t                dst_port{0};    // host byte order
    std::array<uint8_t, 16> dst{};          // network byte order; IPv4 in [0..3], rest 0

    bool operator==(const udp_flow_key&) const = default;
};

inline udp_flow_key make_udp_flow_key(bool ipv6, uint16_t app_port, const uint8_t* dst,
                                      uint16_t dst_port) noexcept {
    udp_flow_key k;
    k.ipv6 = ipv6;
    k.app_port = app_port;
    k.dst_port = dst_port;
    if (dst) {
        std::memcpy(k.dst.data(), dst, ipv6 ? 16 : 4);
    }
    return k;
}

struct udp_flow_key_hash {
    std::size_t operator()(const udp_flow_key& k) const noexcept {
        // 64-bit FNV-1a over the fixed key fields.
        uint64_t h = 14695981039346656037ull;
        auto mix = [&h](uint64_t v) noexcept {
            h ^= v;
            h *= 1099511628211ull;
        };
        mix(k.ipv6 ? 1ull : 0ull);
        mix(static_cast<uint64_t>(k.app_port) | (static_cast<uint64_t>(k.dst_port) << 16));
        uint64_t lo = 0, hi = 0;
        std::memcpy(&lo, k.dst.data(), 8);
        std::memcpy(&hi, k.dst.data() + 8, 8);
        mix(lo);
        mix(hi);
        return static_cast<std::size_t>(h);
    }
};

template <typename Slot>
class udp_relay_index {
public:
    using clock = std::chrono::steady_clock;

    static constexpr std::size_t          kDefaultMaxRelays = 4096;
    static constexpr std::chrono::seconds kIdleTimeout{120};
    static constexpr std::chrono::seconds kCloseGrace{3};

    explicit udp_relay_index(std::size_t max_relays = kDefaultMaxRelays)
        : max_relays_(max_relays) {}

    struct entry {
        Slot                                slot;
        uint32_t                            pid{0};
        uint32_t                            group_id{0};
        clock::time_point                   last_active{};
        std::optional<clock::time_point>    closed_at;
    };

    // Look up an existing flow for outbound reuse. Re-opens a closing slot
    // (same app_port reused or late send), refreshes last_active and updates
    // pid / group_id. Returns nullptr when absent.
    Slot* find_and_touch(const udp_flow_key& key, uint32_t group_id, uint32_t pid,
                         clock::time_point now = clock::now()) {
        auto it = map_.find(key);
        if (it == map_.end()) return nullptr;
        it->second.group_id = group_id;
        it->second.pid = pid;
        it->second.last_active = now;
        it->second.closed_at.reset();
        return &it->second.slot;
    }

    // Look up a flow for an inbound SOCKS5 UDP reply (including slots in the
    // close-grace window so replies already in flight still land if the socket
    // has not actually finished closing).
    Slot* lookup_inbound(const udp_flow_key& key, clock::time_point now = clock::now()) {
        auto it = map_.find(key);
        if (it == map_.end()) return nullptr;
        it->second.last_active = now;
        return &it->second.slot;
    }

    // Check whether a new slot can be inserted, evicting expired entries first
    // and then the oldest closing entry if the table is at capacity. Returns
    // false only when all max_relays_ slots are actively open and unexpired.
    bool make_room(clock::time_point now, std::vector<Slot>& evicted,
                   std::vector<uint16_t>& empty_ports) {
        if (map_.size() < max_relays_) return true;
        prune(now, evicted, empty_ports);
        if (map_.size() < max_relays_) return true;

        // Still full: evict the oldest entry already marked closed (in grace).
        auto oldest_closed = map_.end();
        for (auto it = map_.begin(); it != map_.end(); ++it) {
            if (!it->second.closed_at) continue;
            if (oldest_closed == map_.end() ||
                *it->second.closed_at < *oldest_closed->second.closed_at) {
                oldest_closed = it;
            }
        }
        if (oldest_closed == map_.end()) return false;
        const uint16_t app_port = oldest_closed->first.app_port;
        evicted.push_back(std::move(oldest_closed->second.slot));
        map_.erase(oldest_closed);
        if (!has_port(app_port)) empty_ports.push_back(app_port);
        return true;
    }

    // Insert a newly bound relay slot. Call make_room() first; overwrites any
    // existing entry for the same key and returns any displaced slot in evicted.
    void insert(const udp_flow_key& key, Slot slot, uint32_t group_id, uint32_t pid,
                clock::time_point now, std::vector<Slot>& evicted) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            evicted.push_back(std::move(it->second.slot));
            it->second = entry{std::move(slot), pid, group_id, now, std::nullopt};
            return;
        }
        map_.emplace(key, entry{std::move(slot), pid, group_id, now, std::nullopt});
    }

    // Mark all flows belonging to (pid, app_port, family) as closing so any
    // fire-and-forget datagrams still queued finish forwarding before reaping.
    // family: 0 = both, 4 = IPv4 only, 6 = IPv6 only.
    std::size_t mark_socket_closed(uint32_t pid, uint16_t app_port, uint16_t family,
                                   clock::time_point now = clock::now()) {
        std::size_t marked = 0;
        for (auto& [k, e] : map_) {
            if (k.app_port != app_port) continue;
            if (pid != 0 && e.pid != 0 && e.pid != pid) continue;
            if (family == 4 && k.ipv6) continue;
            if (family == 6 && !k.ipv6) continue;
            if (!e.closed_at) {
                e.closed_at = now;
                ++marked;
            }
        }
        return marked;
    }

    // Remove idle slots and closed slots whose grace period has elapsed.
    // Returns removed slots (to close) and app_ports that now have zero relays.
    std::size_t prune(clock::time_point now, std::vector<Slot>& removed,
                      std::vector<uint16_t>& empty_ports) {
        std::unordered_set<uint16_t> touched_ports;
        std::size_t count = 0;
        for (auto it = map_.begin(); it != map_.end();) {
            const bool close_due =
                it->second.closed_at && (now - *it->second.closed_at >= kCloseGrace);
            const bool idle_due = (now - it->second.last_active >= kIdleTimeout);
            if (close_due || idle_due) {
                touched_ports.insert(it->first.app_port);
                removed.push_back(std::move(it->second.slot));
                it = map_.erase(it);
                ++count;
            } else {
                ++it;
            }
        }
        for (uint16_t port : touched_ports) {
            if (!has_port(port)) empty_ports.push_back(port);
        }
        return count;
    }

    void clear(std::vector<Slot>& removed) {
        removed.reserve(removed.size() + map_.size());
        for (auto& [_, e] : map_) removed.push_back(std::move(e.slot));
        map_.clear();
    }

    bool has_port(uint16_t app_port) const noexcept {
        for (const auto& [k, _] : map_) {
            if (k.app_port == app_port) return true;
        }
        return false;
    }

    std::size_t size() const noexcept { return map_.size(); }
    std::size_t max_relays() const noexcept { return max_relays_; }

private:
    std::size_t max_relays_;
    std::unordered_map<udp_flow_key, entry, udp_flow_key_hash> map_;
};

} // namespace clew::hook
