#pragma once

#define ASIO_STANDALONE
#include <asio.hpp>
#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include "core/log.hpp"
#include "udp/socks5_udp_session.hpp"

namespace clew {
struct UdpProxyGroupConfig {
    std::string host;
    uint16_t port{1080};
    std::string user;
    std::string password;
    bool operator==(const UdpProxyGroupConfig&) const = default;
};
using SessionCreatedCallback = std::function<void(uint16_t, std::shared_ptr<Socks5UdpSession>)>;

class Socks5UdpManager {
public:
    static constexpr size_t kDefaultMaxSessions = 512;
    static constexpr size_t kDefaultMaxPending  = 64;

    struct Stats {
        size_t active{0};
        size_t total{0};
        size_t max_sessions{0};
        size_t sessions_peak{0};
        size_t pending{0};
        size_t max_pending{0};
        size_t pending_peak{0};
        uint64_t rejected_sessions{0};
        uint64_t rejected_pending{0};
    };

    Socks5UdpManager(asio::io_context& ioc,
                     const std::unordered_map<uint32_t, UdpProxyGroupConfig>& groups,
                     size_t max_sessions = kDefaultMaxSessions,
                     size_t max_pending = kDefaultMaxPending)
        : ioc_(ioc)
        , groups_(groups)
        , max_sessions_(max_sessions)
        , max_pending_(max_pending) {}
    ~Socks5UdpManager() { stop(); }

    void set_on_session_created(SessionCreatedCallback cb) {
        std::lock_guard lk(mu_);
        on_session_created_ = std::move(cb);
    }

    // Own a snapshot, rather than reading app's strand-owned map on IO workers.
    void set_groups(const std::unordered_map<uint32_t, UdpProxyGroupConfig>& groups) {
        std::lock_guard lk(mu_);
        if (groups_ == groups) return;
        groups_ = groups;
        clear_all_locked();
    }

    // Called by the single upstream loop. Publish pending ownership so stop()
    // can cancel a handshake; never hold the mutex while awaiting network IO.
    asio::awaitable<std::shared_ptr<Socks5UdpSession>> get_or_create(
        uint16_t app_port, uint32_t group_id,
        std::chrono::steady_clock::duration timeout = std::chrono::seconds(10)) {
        std::shared_ptr<Socks5UdpSession> session;
        {
            std::lock_guard lk(mu_);
            if (stopped_) co_return nullptr;
            auto it = sessions_.find(app_port);
            if (it != sessions_.end()) {
                if (it->second.group_id == group_id && it->second.session->is_alive())
                    co_return it->second.session;
                if (it->second.creating) co_return nullptr;
                erase_entry_locked(it);
            }
            auto group = groups_.find(group_id);
            if (group == groups_.end()) co_return nullptr;
            if (sessions_.size() >= max_sessions_) {
                cleanup_expired_locked(std::chrono::steady_clock::now(), std::chrono::seconds(120));
            }
            if (sessions_.size() >= max_sessions_) {
                const auto n = ++rejected_sessions_;
                if (n == 1 || n % 100 == 0) {
                    PC_LOG_WARN("[SOCKS5-MGR] UDP session cap reached ({}), rejecting port={} (total={})",
                                max_sessions_, app_port, n);
                }
                co_return nullptr;
            }
            if (pending_count_ >= max_pending_) {
                const auto n = ++rejected_pending_;
                if (n == 1 || n % 100 == 0) {
                    PC_LOG_WARN("[SOCKS5-MGR] Pending UDP handshake cap reached ({}), rejecting port={} (total={})",
                                max_pending_, app_port, n);
                }
                co_return nullptr;
            }
            session = std::make_shared<Socks5UdpSession>(
                ioc_, group->second.host, group->second.port,
                socks5_credentials{group->second.user, group->second.password});
            sessions_.emplace(app_port, Entry{session, group_id, true});
            ++pending_count_;
            sessions_peak_ = std::max(sessions_peak_, sessions_.size());
            pending_peak_ = std::max(pending_peak_, pending_count_);
        }

        bool established = co_await session->async_establish(timeout);
        SessionCreatedCallback cb;
        {
            std::lock_guard lk(mu_);
            auto it = sessions_.find(app_port);
            if (stopped_ || it == sessions_.end() || it->second.session != session) {
                session->close();
                co_return nullptr;
            }
            if (!established || !session->is_alive()) {
                erase_entry_locked(it);
                co_return nullptr;
            }
            if (it->second.creating) {
                it->second.creating = false;
                if (pending_count_ > 0) --pending_count_;
            }
            cb = on_session_created_;
            PC_LOG_INFO("[SOCKS5-MGR] Session created for port={} group={} (total={})",
                        app_port, group_id, sessions_.size());
        }
        if (cb) cb(app_port, session);
        co_return session;
    }

    size_t cleanup_expired(
        std::chrono::steady_clock::duration timeout = std::chrono::seconds(120)) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard lk(mu_);
        return cleanup_expired_locked(now, timeout);
    }

    void remove_session(uint16_t app_port) {
        std::lock_guard lk(mu_);
        auto it = sessions_.find(app_port);
        if (it != sessions_.end()) {
            erase_entry_locked(it);
        }
    }

    void stop() {
        if (stopped_.exchange(true)) return;
        std::lock_guard lk(mu_);
        on_session_created_ = nullptr;
        clear_all_locked();
    }

    size_t active_count() const {
        std::lock_guard lk(mu_);
        size_t count = 0;
        for (const auto& [_, entry] : sessions_)
            if (entry.session->is_alive()) ++count;
        return count;
    }

    Stats stats() const {
        std::lock_guard lk(mu_);
        size_t active = 0;
        for (const auto& [_, entry] : sessions_)
            if (entry.session->is_alive()) ++active;
        return {
            .active = active,
            .total = sessions_.size(),
            .max_sessions = max_sessions_,
            .sessions_peak = sessions_peak_,
            .pending = pending_count_,
            .max_pending = max_pending_,
            .pending_peak = pending_peak_,
            .rejected_sessions = rejected_sessions_,
            .rejected_pending = rejected_pending_,
        };
    }

private:
    struct Entry {
        std::shared_ptr<Socks5UdpSession> session;
        uint32_t group_id;
        bool creating;
    };

    void erase_entry_locked(std::unordered_map<uint16_t, Entry>::iterator it) {
        if (it->second.creating && pending_count_ > 0) --pending_count_;
        it->second.session->close();
        sessions_.erase(it);
    }

    void clear_all_locked() {
        for (auto& [_, entry] : sessions_) entry.session->close();
        sessions_.clear();
        pending_count_ = 0;
    }

    size_t cleanup_expired_locked(std::chrono::steady_clock::time_point now,
                                  std::chrono::steady_clock::duration timeout) {
        size_t removed = 0;
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            auto& entry = it->second;
            if (!entry.creating && (!entry.session->is_alive() ||
                                    now - entry.session->last_active() >= timeout)) {
                entry.session->close();
                it = sessions_.erase(it);
                ++removed;
            } else ++it;
        }
        return removed;
    }

    asio::io_context& ioc_;
    std::unordered_map<uint32_t, UdpProxyGroupConfig> groups_;
    size_t max_sessions_;
    size_t max_pending_;
    std::atomic<bool> stopped_{false};
    mutable std::mutex mu_;
    std::unordered_map<uint16_t, Entry> sessions_;
    size_t pending_count_{0};
    size_t sessions_peak_{0};
    size_t pending_peak_{0};
    uint64_t rejected_sessions_{0};
    uint64_t rejected_pending_{0};
    SessionCreatedCallback on_session_created_;
};
} // namespace clew
