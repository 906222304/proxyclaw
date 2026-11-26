#pragma once

// Hook-mode per-flow loopback UDP relay (interception.mode = "hook").
//
// Each (family, app_local_port, remote_ip, remote_port) flow gets one bound
// loopback UDP socket (127.0.0.1:R or [::1]:R). The injected DLL rewrites
// ONLY the sockaddr (outbound dst -> loopback:R, inbound src loopback:R ->
// original remote), leaving payload buffers completely untouched so IOCP /
// overlapped / QUIC callers never see modified wire bytes.
//
// Outbound datagrams received on loopback:R are queued per app_local_port and
// serialized through one flush_port coroutine per port so Socks5UdpManager::
// get_or_create() is never raced for the same port. Inbound SOCKS5 replies on
// that port's session are decoded and sent raw from the matching loopback:R
// back to loopback:app_local_port.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "core/log.hpp"
#include "hook/hook_udp_table.hpp"
#include "udp/socks5_udp_codec.hpp"
#include "udp/socks5_udp_manager.hpp"

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace clew::hook {

class udp_relay {
public:
    static constexpr std::size_t kMaxTotalPackets = 4096;
    static constexpr std::size_t kMaxTotalBytes   = 16u * 1024u * 1024u;
    static constexpr std::size_t kMaxPortPackets  = 256;

    udp_relay(asio::io_context& ioc, Socks5UdpManager& socks5_mgr)
        : strand_(asio::make_strand(ioc))
        , socks5_mgr_(socks5_mgr) {}

    ~udp_relay() { stop(); }

    udp_relay(const udp_relay&) = delete;
    udp_relay& operator=(const udp_relay&) = delete;

    void start() {
        running_.store(true, std::memory_order_release);
        socks5_mgr_.set_on_session_created(
            [this](uint16_t app_port, std::shared_ptr<Socks5UdpSession> session) {
                if (!running_.load(std::memory_order_acquire)) return;
                asio::co_spawn(strand_, downstream_for_session(app_port, std::move(session)),
                               asio::detached);
            });
    }

    void stop() {
        if (!running_.exchange(false, std::memory_order_acq_rel)) return;
        socks5_mgr_.set_on_session_created(nullptr);
        socks5_mgr_.stop();

        std::vector<std::shared_ptr<relay_slot>> to_close;
        {
            std::lock_guard lock(mu_);
            index_.clear(to_close);
        }
        asio::dispatch(strand_, [this, slots = std::move(to_close)]() mutable {
            for (auto& s : slots) s->close();
            for (auto& [_, ps] : ports_) {
                for (const auto& q : ps.queue) release(q.payload.size());
                ps.queue.clear();
                ps.flushing = false;
            }
            ports_.clear();
        });
        PC_LOG_INFO("[HOOK-UDP] stopped (up={}, down={}, dropped={}, filtered={})",
                    packets_up_.load(), packets_down_.load(), packets_dropped_.load(),
                    packets_filtered_.load());
    }

    // Bind (or reuse) a loopback UDP relay socket for this flow. Returns the
    // loopback relay port, or 0 if stopped, at relay cap, or bind failed.
    uint16_t ensure_flow(bool ipv6, uint16_t app_port, const uint8_t* dst,
                         uint16_t dst_port, uint32_t group_id, uint32_t pid) {
        if (!running_.load(std::memory_order_acquire) || app_port == 0 || dst_port == 0) return 0;

        const udp_flow_key key = make_udp_flow_key(ipv6, app_port, dst, dst_port);
        const auto now = clock::now();

        {
            std::lock_guard lock(mu_);
            if (auto* existing = index_.find_and_touch(key, group_id, pid, now)) {
                (*existing)->group_id.store(group_id, std::memory_order_relaxed);
                return (*existing)->relay_port;
            }
        }

        // Bind outside mu_ so the mutex only guards fast in-memory lookups.
        asio::ip::udp::socket sock(strand_);
        try {
            const auto proto = ipv6 ? asio::ip::udp::v6() : asio::ip::udp::v4();
            sock.open(proto);
            BOOL connreset = FALSE;
            DWORD bytes_returned = 0;
            WSAIoctl(sock.native_handle(), SIO_UDP_CONNRESET,
                     &connreset, sizeof(connreset),
                     nullptr, 0, &bytes_returned, nullptr, nullptr);
            asio::error_code buf_ec;
            sock.set_option(asio::socket_base::receive_buffer_size(256 * 1024), buf_ec);
            const asio::ip::udp::endpoint ep(
                ipv6 ? asio::ip::address(asio::ip::address_v6::loopback())
                     : asio::ip::address(asio::ip::address_v4::loopback()),
                0);
            sock.bind(ep);
        } catch (const std::exception& e) {
            PC_LOG_WARN("[HOOK-UDP] loopback bind{} failed: {}", ipv6 ? " (v6)" : "", e.what());
            return 0;
        }

        const uint16_t relay_port = sock.local_endpoint().port();
        auto slot = std::make_shared<relay_slot>(std::move(sock), key, relay_port, group_id);

        std::vector<std::shared_ptr<relay_slot>> evicted;
        std::vector<uint16_t> empty_ports;
        bool inserted = false;
        {
            std::lock_guard lock(mu_);
            if (!running_.load(std::memory_order_acquire)) {
                slot->close();
                return 0;
            }
            if (auto* existing = index_.find_and_touch(key, group_id, pid, now)) {
                (*existing)->group_id.store(group_id, std::memory_order_relaxed);
                slot->close();
                return (*existing)->relay_port;
            }
            if (index_.make_room(now, evicted, empty_ports)) {
                index_.insert(key, slot, group_id, pid, now, evicted);
                inserted = true;
            }
        }

        cleanup_removed(std::move(evicted), std::move(empty_ports));

        if (!inserted) {
            slot->close();
            const auto n = cap_rejected_.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1 || n % 100 == 0) {
                PC_LOG_WARN("[HOOK-UDP] relay table full ({} active), rejected flow (total={})",
                            udp_relay_index<std::shared_ptr<relay_slot>>::kDefaultMaxRelays, n);
            }
            return 0;
        }

        asio::co_spawn(strand_, read_loop(slot), asio::detached);
        return relay_port;
    }

    // Mark relays for a closing app socket so queued fire-and-forget datagrams
    // can still drain during the short close-grace window.
    void on_socket_close(uint32_t pid, uint16_t app_port, uint16_t family) {
        if (app_port == 0) return;
        std::lock_guard lock(mu_);
        index_.mark_socket_closed(pid, app_port, family, clock::now());
    }

    // Called periodically from hook::mode::schedule_sweep().
    void prune() {
        std::vector<std::shared_ptr<relay_slot>> removed;
        std::vector<uint16_t> empty_ports;
        {
            std::lock_guard lock(mu_);
            index_.prune(clock::now(), removed, empty_ports);
        }
        cleanup_removed(std::move(removed), std::move(empty_ports));
        socks5_mgr_.cleanup_expired();
    }

    std::size_t active_relays() const {
        std::lock_guard lock(mu_);
        return index_.size();
    }
    static constexpr std::size_t max_relays() noexcept {
        return udp_relay_index<std::shared_ptr<relay_slot>>::kDefaultMaxRelays;
    }
    uint64_t packets_up() const noexcept       { return packets_up_.load(std::memory_order_relaxed); }
    uint64_t packets_down() const noexcept     { return packets_down_.load(std::memory_order_relaxed); }
    uint64_t packets_dropped() const noexcept  { return packets_dropped_.load(std::memory_order_relaxed); }
    uint64_t packets_filtered() const noexcept { return packets_filtered_.load(std::memory_order_relaxed); }
    uint64_t cap_rejected() const noexcept     { return cap_rejected_.load(std::memory_order_relaxed); }

private:
    using clock = std::chrono::steady_clock;

    struct relay_slot {
        relay_slot(asio::ip::udp::socket s, udp_flow_key k, uint16_t rport, uint32_t gid)
            : sock(std::move(s)), key(k), relay_port(rport), group_id(gid) {}

        // Only call on strand_ (or before the slot is published to index_).
        void close() {
            closed.store(true, std::memory_order_release);
            asio::error_code ec;
            sock.close(ec);
        }

        asio::ip::udp::socket  sock;
        udp_flow_key           key;
        uint16_t               relay_port{0};
        std::atomic<uint32_t>  group_id{0};
        std::atomic<bool>      closed{false};
    };

    struct outbound_dgram {
        udp_flow_key         key;
        uint32_t             group_id{0};
        std::vector<uint8_t> payload;
    };

    struct port_state {
        std::deque<outbound_dgram> queue;
        bool                       flushing{false};
    };

    void release(std::size_t bytes) noexcept {
        queued_packets_.fetch_sub(1, std::memory_order_acq_rel);
        queued_bytes_.fetch_sub(bytes, std::memory_order_acq_rel);
    }

    void note_drop(const char* why) {
        const auto n = packets_dropped_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n == 1 || n % 1000 == 0) {
            PC_LOG_WARN("[HOOK-UDP] dropped datagram ({}), total={}", why, n);
        }
    }

    void cleanup_removed(std::vector<std::shared_ptr<relay_slot>> removed,
                         std::vector<uint16_t> empty_ports) {
        for (uint16_t port : empty_ports) {
            socks5_mgr_.remove_session(port);
        }
        if (removed.empty() && empty_ports.empty()) return;
        asio::dispatch(strand_, [this, slots = std::move(removed),
                                 ports = std::move(empty_ports)]() mutable {
            for (auto& s : slots) s->close();
            for (uint16_t port : ports) {
                auto it = ports_.find(port);
                if (it != ports_.end() && !it->second.flushing && it->second.queue.empty()) {
                    ports_.erase(it);
                }
            }
        });
    }

    // Runs on strand_: receives raw app datagrams on loopback:R and queues
    // them for the per-app_port SOCKS5 flush coroutine.
    asio::awaitable<void> read_loop(std::shared_ptr<relay_slot> slot) {
        std::vector<uint8_t> buf(65536);
        auto last_touch = clock::now();

        while (running_.load(std::memory_order_acquire) &&
               !slot->closed.load(std::memory_order_acquire)) {
            asio::ip::udp::endpoint from;
            auto [ec, n] = co_await slot->sock.async_receive_from(
                asio::buffer(buf), from, asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (ec == asio::error::connection_reset) continue;
                if (running_.load(std::memory_order_acquire) &&
                    !slot->closed.load(std::memory_order_acquire)) {
                    PC_LOG_DEBUG("[HOOK-UDP] relay {} recv error: {}", slot->relay_port, ec.message());
                }
                break;
            }
            // Accept only packets from the owning local loopback port.
            if (!from.address().is_loopback() || from.port() != slot->key.app_port) {
                packets_filtered_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            const auto now = clock::now();
            if (now - last_touch >= std::chrono::seconds(10)) {
                last_touch = now;
                std::lock_guard lock(mu_);
                index_.lookup_inbound(slot->key, now);
            }

            if (queued_packets_.fetch_add(1, std::memory_order_acq_rel) >= kMaxTotalPackets) {
                queued_packets_.fetch_sub(1, std::memory_order_acq_rel);
                note_drop("queue full");
                continue;
            }
            if (queued_bytes_.fetch_add(n, std::memory_order_acq_rel) + n > kMaxTotalBytes) {
                release(n);
                note_drop("queue bytes full");
                continue;
            }

            auto& ps = ports_[slot->key.app_port];
            if (ps.queue.size() >= kMaxPortPackets) {
                release(n);
                note_drop("port queue full");
                continue;
            }

            outbound_dgram d;
            d.key = slot->key;
            d.group_id = slot->group_id.load(std::memory_order_relaxed);
            d.payload.assign(buf.data(), buf.data() + n);
            ps.queue.push_back(std::move(d));

            if (!ps.flushing) {
                ps.flushing = true;
                asio::co_spawn(strand_, flush_port(slot->key.app_port), asio::detached);
            }
        }
    }

    // Runs on strand_: single upstream pump per app_port so Socks5UdpManager::
    // get_or_create() is never invoked concurrently for the same port.
    asio::awaitable<void> flush_port(uint16_t app_port) {
        while (true) {
            auto it = ports_.find(app_port);
            if (it == ports_.end()) co_return;
            if (it->second.queue.empty() || !running_.load(std::memory_order_acquire)) {
                for (const auto& q : it->second.queue) release(q.payload.size());
                it->second.queue.clear();
                it->second.flushing = false;
                bool keep = false;
                {
                    std::lock_guard lock(mu_);
                    keep = index_.has_port(app_port);
                }
                if (!keep) ports_.erase(it);
                co_return;
            }

            outbound_dgram d = std::move(it->second.queue.front());
            it->second.queue.pop_front();
            const std::size_t bytes = d.payload.size();

            // `it` is invalid after co_await.
            auto socks5 = co_await socks5_mgr_.get_or_create(app_port, d.group_id);
            if (!socks5) {
                release(bytes);
                if (auto again = ports_.find(app_port); again != ports_.end()) {
                    for (const auto& q : again->second.queue) {
                        release(q.payload.size());
                        note_drop("no proxy session");
                    }
                    again->second.queue.clear();
                }
                note_drop("no proxy session");
                PC_LOG_WARN("[HOOK-UDP] no SOCKS5 UDP session for port={} group={}",
                            app_port, d.group_id);
                continue;
            }

            std::vector<uint8_t> frame;
            if (d.key.ipv6) {
                frame = socks5_udp::encode6(d.key.dst.data(), d.key.dst_port,
                                            d.payload.data(), d.payload.size());
            } else {
                uint32_t dst_net = 0;
                std::memcpy(&dst_net, d.key.dst.data(), 4);
                frame = socks5_udp::encode(dst_net, d.key.dst_port,
                                           d.payload.data(), d.payload.size());
            }
            release(bytes);

            const bool sent = co_await socks5->async_send_udp(std::move(frame));
            if (sent) {
                packets_up_.fetch_add(1, std::memory_order_relaxed);
            } else {
                note_drop("socks5 send failed");
            }
        }
    }

    // Runs on strand_: receives SOCKS5 UDP replies for app_port, unwraps the
    // SOCKS5 header, and forwards raw payload from the matching loopback relay
    // socket to loopback:app_port.
    asio::awaitable<void> downstream_for_session(
        uint16_t app_port, std::shared_ptr<Socks5UdpSession> session) {
        std::vector<uint8_t> buf(65536);

        while (session->is_alive() && running_.load(std::memory_order_acquire)) {
            auto [n, ec] = co_await session->async_recv_udp(buf.data(), buf.size());
            if (ec) {
                if (session->is_alive() && running_.load(std::memory_order_acquire)) {
                    PC_LOG_DEBUG("[HOOK-UDP] downstream recv error port={}: {}",
                                 app_port, ec.message());
                }
                break;
            }
            if (n == 0) continue;

            const auto frame = socks5_udp::decode(buf.data(), n);
            if (!frame) continue;

            udp_flow_key key;
            if (frame->v6) {
                key = make_udp_flow_key(true, app_port, frame->addr6.data(), frame->port_host);
            } else {
                uint8_t v4[4]{};
                std::memcpy(v4, &frame->addr_net, 4);
                key = make_udp_flow_key(false, app_port, v4, frame->port_host);
            }

            std::shared_ptr<relay_slot> slot;
            {
                std::lock_guard lock(mu_);
                if (auto* found = index_.lookup_inbound(key, clock::now())) {
                    slot = *found;
                }
            }
            if (!slot || slot->closed.load(std::memory_order_acquire)) {
                packets_filtered_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            const asio::ip::udp::endpoint app_ep(
                frame->v6 ? asio::ip::address(asio::ip::address_v6::loopback())
                          : asio::ip::address(asio::ip::address_v4::loopback()),
                app_port);
            auto [send_ec, sent] = co_await slot->sock.async_send_to(
                asio::buffer(frame->data, frame->data_len), app_ep,
                asio::as_tuple(asio::use_awaitable));
            (void)sent;
            if (!send_ec) {
                packets_down_.fetch_add(1, std::memory_order_relaxed);
            } else if (running_.load(std::memory_order_acquire) &&
                       !slot->closed.load(std::memory_order_acquire)) {
                PC_LOG_DEBUG("[HOOK-UDP] reply send to loopback:{} failed: {}",
                             app_port, send_ec.message());
            }
        }
    }

    asio::strand<asio::io_context::executor_type> strand_;
    Socks5UdpManager& socks5_mgr_;
    std::atomic<bool> running_{false};

    mutable std::mutex mu_;
    udp_relay_index<std::shared_ptr<relay_slot>> index_;

    // strand_-only
    std::unordered_map<uint16_t, port_state> ports_;

    std::atomic<std::size_t> queued_packets_{0};
    std::atomic<std::size_t> queued_bytes_{0};
    std::atomic<uint64_t>    packets_up_{0};
    std::atomic<uint64_t>    packets_down_{0};
    std::atomic<uint64_t>    packets_dropped_{0};
    std::atomic<uint64_t>    packets_filtered_{0};
    std::atomic<uint64_t>    cap_rejected_{0};
};

} // namespace clew::hook
