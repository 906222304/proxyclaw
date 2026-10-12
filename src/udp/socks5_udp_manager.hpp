#pragma once

#define ASIO_STANDALONE
#include <asio.hpp>
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
    bool operator==(const UdpProxyGroupConfig&) const = default;
};
using SessionCreatedCallback = std::function<void(uint16_t, std::shared_ptr<Socks5UdpSession>)>;

class Socks5UdpManager {
public:
    Socks5UdpManager(asio::io_context& ioc,
                     const std::unordered_map<uint32_t, UdpProxyGroupConfig>& groups)
        : ioc_(ioc), groups_(groups) {}
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
        for (auto& [_, entry] : sessions_) entry.session->close();
        sessions_.clear();
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
                it->second.session->close();
                sessions_.erase(it);
            }
            auto group = groups_.find(group_id);
            if (group == groups_.end()) co_return nullptr;
            session = std::make_shared<Socks5UdpSession>(ioc_, group->second.host, group->second.port);
            sessions_.emplace(app_port, Entry{session, group_id, true});
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
                session->close();
                sessions_.erase(it);
                co_return nullptr;
            }
            it->second.creating = false;
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

    void remove_session(uint16_t app_port) {
        std::lock_guard lk(mu_);
        auto it = sessions_.find(app_port);
        if (it != sessions_.end()) {
            it->second.session->close();
            sessions_.erase(it);
        }
    }

    void stop() {
        if (stopped_.exchange(true)) return;
        std::lock_guard lk(mu_);
        on_session_created_ = nullptr;
        for (auto& [_, entry] : sessions_) entry.session->close();
        sessions_.clear();
    }

    size_t active_count() const {
        std::lock_guard lk(mu_);
        size_t count = 0;
        for (const auto& [_, entry] : sessions_)
            if (entry.session->is_alive()) ++count;
        return count;
    }

private:
    struct Entry {
        std::shared_ptr<Socks5UdpSession> session;
        uint32_t group_id;
        bool creating;
    };
    asio::io_context& ioc_;
    std::unordered_map<uint32_t, UdpProxyGroupConfig> groups_;
    std::atomic<bool> stopped_{false};
    mutable std::mutex mu_;
    std::unordered_map<uint16_t, Entry> sessions_;
    SessionCreatedCallback on_session_created_;
};
} // namespace clew
