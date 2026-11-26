#pragma once

// UDP Session Table: maps app src_port -> original destination + metadata.
// Written by UDP NETWORK workers (on intercept), read by UDP Relay.
//
// Synchronization: shared_mutex (NETWORK workers = exclusive write, relay = shared read).
// Low contention: writes only on new src_port first seen, reads on every relay packet.

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace clew {

// One app port may send both families (a dual-stack socket); each family
// keeps its own app-side address and interface for reply injection. The
// orig_dst_* fields are the most recent destination, of either family.
struct UdpSession {
    uint32_t orig_dst_addr{};   // network byte order (raw from IP header), IPv4
    uint16_t orig_dst_port{};   // network byte order (raw from UDP header)
    bool     orig_dst_v6{false};
    std::array<uint8_t, 16> orig_dst_addr6{};
    uint32_t app_src_addr{};    // network byte order
    uint16_t app_src_port{};    // host byte order (key)
    uint32_t pid{};
    uint32_t group_id{};
    uint32_t ifidx{};
    uint32_t subifidx{};
    bool has_v4{false};
    // IPv6 side (ipv6.mode = proxy)
    bool has_v6{false};
    std::array<uint8_t, 16> app_src_addr6{};
    uint32_t ifidx6{};
    uint32_t subifidx6{};
    std::chrono::steady_clock::time_point last_active{std::chrono::steady_clock::now()};
};

class UdpSessionTable {
public:
    static constexpr size_t kDefaultMaxSessions = 2048;

    struct Stats {
        size_t   active{0};
        size_t   max_sessions{0};
        size_t   peak{0};
        uint64_t rejected_cap{0};
    };

    explicit UdpSessionTable(size_t max_sessions = kDefaultMaxSessions)
        : max_sessions_(max_sessions) {}

    // Insert or update session (called from NETWORK workers).
    // The other family's app-side fields of an existing entry are kept, so
    // a dual-stack socket's IPv4 and IPv6 replies both find their route.
    // Returns false when the table is at capacity even after pruning expired
    // sessions; updating an existing port always succeeds.
    bool upsert(uint16_t app_port, const UdpSession& session,
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) {
        std::unique_lock lk(mu_);
        if (auto it = sessions_.find(app_port); it != sessions_.end()) {
            UdpSession merged = session;
            const UdpSession& old = it->second;
            if (!merged.has_v4 && old.has_v4) {
                merged.has_v4 = true;
                merged.app_src_addr = old.app_src_addr;
                merged.ifidx = old.ifidx;
                merged.subifidx = old.subifidx;
            }
            if (!merged.has_v6 && old.has_v6) {
                merged.has_v6 = true;
                merged.app_src_addr6 = old.app_src_addr6;
                merged.ifidx6 = old.ifidx6;
                merged.subifidx6 = old.subifidx6;
            }
            it->second = merged;
            return true;
        }
        if (sessions_.size() >= max_sessions_) {
            cleanup_expired_locked(now, std::chrono::seconds(120));
        }
        if (sessions_.size() >= max_sessions_) {
            ++rejected_cap_;
            return false;
        }
        sessions_.emplace(app_port, session);
        peak_ = std::max(peak_, sessions_.size());
        return true;
    }

    // Lookup session (called from relay)
    std::optional<UdpSession> lookup(uint16_t app_port) const {
        std::shared_lock lk(mu_);
        auto it = sessions_.find(app_port);
        if (it != sessions_.end())
            return it->second;
        return std::nullopt;
    }

    // Update last_active timestamp (called from relay on upstream send)
    void touch(uint16_t app_port) {
        std::unique_lock lk(mu_);
        auto it = sessions_.find(app_port);
        if (it != sessions_.end())
            it->second.last_active = std::chrono::steady_clock::now();
    }

    // Remove session
    void remove(uint16_t app_port) {
        std::unique_lock lk(mu_);
        sessions_.erase(app_port);
    }

    // Remove expired sessions. Returns number removed.
    size_t cleanup_expired(std::chrono::seconds timeout = std::chrono::seconds(120),
                           std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) {
        std::unique_lock lk(mu_);
        return cleanup_expired_locked(now, timeout);
    }

    // Get all active sessions (for API)
    std::vector<UdpSession> snapshot() const {
        std::shared_lock lk(mu_);
        std::vector<UdpSession> result;
        result.reserve(sessions_.size());
        for (const auto& [_, s] : sessions_)
            result.push_back(s);
        return result;
    }

    size_t size() const {
        std::shared_lock lk(mu_);
        return sessions_.size();
    }

    Stats stats() const {
        std::shared_lock lk(mu_);
        return {
            .active       = sessions_.size(),
            .max_sessions = max_sessions_,
            .peak         = peak_,
            .rejected_cap = rejected_cap_,
        };
    }

private:
    static constexpr uint16_t kDnsPortNet =
        (std::endian::native == std::endian::little)
            ? static_cast<uint16_t>((53u & 0xFFu) << 8)
            : uint16_t{53u};

    size_t cleanup_expired_locked(std::chrono::steady_clock::time_point now,
                                  std::chrono::seconds timeout) {
        // DNS (port 53) gets shorter timeout
        return std::erase_if(sessions_, [now, timeout](const auto& kv) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - kv.second.last_active);
            auto effective_timeout = (kv.second.orig_dst_port == kDnsPortNet)
                                    ? std::chrono::seconds(10)
                                    : timeout;
            return age > effective_timeout;
        });
    }

    size_t max_sessions_;
    mutable std::shared_mutex mu_;
    std::unordered_map<uint16_t, UdpSession> sessions_;
    size_t peak_{0};
    uint64_t rejected_cap_{0};
};

} // namespace clew
