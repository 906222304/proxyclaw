#pragma once

// ipv6_egress — per proxy group "can this proxy reach IPv6?" state for
// ipv6.mode = proxy.
//
// A proxied IPv6 TCP connection is accepted locally before the SOCKS5 CONNECT
// runs, so when the proxy has no IPv6 egress the application sees an
// established connection that then dies, and never falls back to IPv4. This
// table learns from the CONNECT replies and the IPv6 probe: once a group is
// marked, its IPv6 TCP connects are refused at the SYN and its IPv6 UDP is
// dropped (the block path), so applications fall back to IPv4 through the
// same proxy. A mark lasts `cooldown`; after it expires the next flow tries
// again and a single further failure re-marks the group.
//
// What counts (RFC 1928 REP):
//   0x08 address type not supported   marks at once (the proxy has no ATYP 4)
//   0x01 general failure, 0x03 network unreachable, 0x04 host unreachable
//                                      mark after `threshold` in a row
//   anything else (refused, ruleset, TTL...) is about the target, not IPv6
// A successful IPv6 CONNECT clears the group.
//
// Thread-safe: the relay reports from IO workers, the SOCKET / NETWORK
// workers read. Reads take a lock-free fast path while no group is marked.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace clew {

class ipv6_egress {
public:
    using clock = std::chrono::steady_clock;

    static constexpr int threshold = 2;
    static constexpr std::chrono::seconds default_cooldown{300};

    explicit ipv6_egress(clock::duration cooldown = default_cooldown) : cooldown_(cooldown) {}

    struct entry {
        uint32_t    group_id{};
        bool        unavailable{};
        int64_t     seconds_left{};   // while unavailable
        std::string reason;           // last failure
    };

    // True when the SOCKS5 reply code says the proxy cannot reach IPv6.
    static constexpr bool counts(uint8_t rep) noexcept {
        return rep == 0x01 || rep == 0x03 || rep == 0x04 || rep == 0x08;
    }

    void report_success(uint32_t group_id) {
        std::lock_guard lk(mu_);
        auto it = groups_.find(group_id);
        if (it == groups_.end()) return;
        if (it->second.marked) marked_.fetch_sub(1, std::memory_order_relaxed);
        groups_.erase(it);
    }

    // A failed IPv6 CONNECT with SOCKS5 reply `rep`. Returns true when this
    // report marked the group unavailable.
    bool report_failure(uint32_t group_id, uint8_t rep, clock::time_point now = clock::now()) {
        if (!counts(rep)) return false;
        std::lock_guard lk(mu_);
        auto& st = groups_[group_id];
        expire(st, now);
        st.fails = (rep == 0x08) ? threshold : st.fails + 1;
        st.reason = reply_name(rep);
        if (st.fails >= threshold && !st.marked) {
            mark(st, now);
            return true;
        }
        return false;
    }

    // The probe found no IPv6 egress (the proxy could not reach the target).
    void mark_unavailable(uint32_t group_id, std::string reason, clock::time_point now = clock::now()) {
        std::lock_guard lk(mu_);
        auto& st = groups_[group_id];
        expire(st, now);
        st.fails = threshold;
        st.reason = std::move(reason);
        if (!st.marked) mark(st, now);
        else st.until = now + cooldown_;
    }

    [[nodiscard]] bool unavailable(uint32_t group_id, clock::time_point now = clock::now()) const {
        if (marked_.load(std::memory_order_relaxed) == 0) return false;
        std::lock_guard lk(mu_);
        auto it = groups_.find(group_id);
        if (it == groups_.end()) return false;
        expire(it->second, now);
        return it->second.marked;
    }

    [[nodiscard]] std::vector<entry> snapshot(clock::time_point now = clock::now()) const {
        std::lock_guard lk(mu_);
        std::vector<entry> out;
        for (auto& [id, st] : groups_) {
            expire(st, now);
            entry e;
            e.group_id = id;
            e.unavailable = st.marked;
            if (st.marked)
                e.seconds_left = std::chrono::duration_cast<std::chrono::seconds>(st.until - now).count();
            e.reason = st.reason;
            out.push_back(std::move(e));
        }
        return out;
    }

    void clear() {
        std::lock_guard lk(mu_);
        groups_.clear();
        marked_.store(0, std::memory_order_relaxed);
    }

    static std::string reply_name(uint8_t rep) {
        switch (rep) {
        case 0x01: return "general failure";
        case 0x03: return "network unreachable";
        case 0x04: return "host unreachable";
        case 0x08: return "address type not supported";
        default:   return "error " + std::to_string(rep);
        }
    }

private:
    struct state {
        int               fails = 0;
        bool              marked = false;
        clock::time_point until{};
        std::string       reason;
    };

    void mark(state& st, clock::time_point now) const {
        st.marked = true;
        st.until = now + cooldown_;
        marked_.fetch_add(1, std::memory_order_relaxed);
    }

    // An expired mark goes half-open: one more failure re-marks.
    void expire(state& st, clock::time_point now) const {
        if (st.marked && now >= st.until) {
            st.marked = false;
            st.fails = threshold - 1;
            marked_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    const clock::duration cooldown_;
    // Reads expire marks lazily, hence mutable.
    mutable std::mutex mu_;
    mutable std::unordered_map<uint32_t, state> groups_;
    mutable std::atomic<int> marked_{0};
};

} // namespace clew
