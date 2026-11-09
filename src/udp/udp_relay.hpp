#pragma once

// UDP Relay: takes hijacked datagrams from the UDP NETWORK layer, forwards
// them via SOCKS5 UDP ASSOCIATE, and injects replies back to the application
// via WinDivert.
//
// Architecture (per-local-port sessions, per-packet addressing):
//   submit() (NETWORK worker thread) -> bounded post onto strand_
//   on_outbound (strand_)  -> per-port queue + peer set -> flush_port coroutine
//   flush_port  (strand_, one per app_port while it has queued datagrams)
//       -> get/create SOCKS5 session for that port -> encode with the
//          datagram's own destination -> proxy
//   downstream_for_session (strand_, per app_port)
//       -> SOCKS5 decode -> drop unless from a peer this port sent to
//       -> inject with the reply's real source address
//
// Each hijacked UDP socket gets its own SOCKS5 UDP ASSOCIATE session (RFC 1928
// compliant). A slow handshake for one port only queues that port's datagrams;
// other ports keep flowing.

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/use_awaitable.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <unordered_map>
#include <vector>
#include "core/log.hpp"

#include "udp/socks5_udp_codec.hpp"
#include "udp/socks5_udp_manager.hpp"
#include "udp/udp_flow.hpp"
#include "udp/udp_session_table.hpp"

namespace clew {

class UdpRelay final : public UdpOutboundSink {
public:
    UdpRelay(asio::io_context& ioc,
             UdpSessionTable& session_table,
             Socks5UdpManager& socks5_mgr,
             HANDLE wd_handle,
             UdpQueueLimits limits = {})
        : session_table_(session_table)
        , socks5_mgr_(socks5_mgr)
        , wd_handle_(wd_handle)
        , limits_(limits)
        , strand_(asio::make_strand(ioc))
        , cleanup_timer_(strand_)
    {
        // When a new per-port SOCKS5 session is created, spawn its downstream coroutine
        socks5_mgr_.set_on_session_created(
            [this](uint16_t app_port, std::shared_ptr<Socks5UdpSession> session) {
                spawn_downstream(app_port, std::move(session));
            });
    }

    ~UdpRelay() { stop(); }

    bool start() {
        running_ = true;
        asio::co_spawn(strand_, cleanup_loop(), asio::detached);
        PC_LOG_INFO("[UDP-RELAY] Started (queue limits: {} pkts, {} MB, {} per port)",
                    limits_.max_total_packets, limits_.max_total_bytes >> 20,
                    limits_.max_port_packets);
        return true;
    }

    // Called from UDP NETWORK worker threads. Never blocks; drops when the
    // relay is stopped or the shared queue is full.
    bool submit(UdpOutbound&& datagram) override {
        if (!running_.load(std::memory_order_acquire)) return false;
        const size_t bytes = datagram.payload.size();
        if (queued_packets_.fetch_add(1, std::memory_order_acq_rel) >= limits_.max_total_packets) {
            queued_packets_.fetch_sub(1, std::memory_order_acq_rel);
            note_drop("queue full");
            return false;
        }
        if (queued_bytes_.fetch_add(bytes, std::memory_order_acq_rel) + bytes > limits_.max_total_bytes) {
            release(bytes);
            note_drop("queue full");
            return false;
        }
        asio::post(strand_, [this, d = std::move(datagram)]() mutable {
            on_outbound(std::move(d));
        });
        return true;
    }

    // Shutdown order requirement:
    //   1. socks5_mgr.stop()  — closes sessions, causes downstream coroutines to error out
    //   2. udp_relay->stop()  — clears callback, stops accepting datagrams
    //   3. NETWORK layer close() — joins the workers that call submit()
    //   4. ioc.stop() + workers.join() — no more handlers may execute
    //   5. UdpRelay destruction; remaining coroutine frames are destroyed by ioc
    void stop() {
        if (stopped_) return;
        stopped_ = true;
        running_ = false;

        socks5_mgr_.set_on_session_created(nullptr);

        asio::dispatch(strand_, [this] {
            cleanup_timer_.cancel();
        });

        PC_LOG_INFO("[UDP-RELAY] Stopped (up={}, down={}, injected={}, dropped={}, filtered={})",
                     upstream_count_.load(), downstream_count_.load(), injected_count_.load(),
                     dropped_count_.load(), filtered_count_.load());
    }

    uint64_t upstream_count() const { return upstream_count_; }
    uint64_t downstream_count() const { return downstream_count_; }
    uint64_t injected_count() const { return injected_count_; }
    uint64_t dropped_count() const { return dropped_count_; }
    uint64_t filtered_count() const { return filtered_count_; }

private:
    struct PortState {
        std::deque<UdpOutbound> queue;
        UdpPeerSet peers;
        bool flushing{false};
    };

    UdpSessionTable& session_table_;
    Socks5UdpManager& socks5_mgr_;
    HANDLE wd_handle_;
    UdpQueueLimits limits_;

    asio::strand<asio::io_context::executor_type> strand_;
    asio::steady_timer cleanup_timer_;
    bool stopped_{false};
    std::atomic<bool> running_{false};

    // strand_-only
    std::unordered_map<uint16_t, PortState> ports_;

    std::atomic<size_t> queued_packets_{0};
    std::atomic<size_t> queued_bytes_{0};

    std::atomic<uint64_t> upstream_count_{0};
    std::atomic<uint64_t> downstream_count_{0};
    std::atomic<uint64_t> injected_count_{0};
    std::atomic<uint64_t> dropped_count_{0};
    std::atomic<uint64_t> filtered_count_{0};

    void release(size_t bytes) {
        queued_packets_.fetch_sub(1, std::memory_order_acq_rel);
        queued_bytes_.fetch_sub(bytes, std::memory_order_acq_rel);
    }

    void note_drop(const char* why) {
        const auto n = dropped_count_.fetch_add(1, std::memory_order_relaxed) + 1;
        // Log the first drop and then every 1000th, so a flood stays visible
        // without flooding the log.
        if (n == 1 || n % 1000 == 0)
            PC_LOG_WARN("[UDP-RELAY] Dropped datagram ({}), total dropped={}", why, n);
    }

    // Spawn a downstream coroutine for a newly created per-port session
    void spawn_downstream(uint16_t app_port, std::shared_ptr<Socks5UdpSession> session) {
        asio::co_spawn(strand_,
            downstream_for_session(app_port, std::move(session)),
            asio::detached);
    }

    // ---- Upstream: NETWORK layer -> per-port queue -> SOCKS5 -> proxy ----

    void on_outbound(UdpOutbound d) {
        const size_t bytes = d.payload.size();
        if (!running_) { release(bytes); return; }
        auto& port = ports_[d.app_port];
        if (port.queue.size() >= limits_.max_port_packets) {
            release(bytes);
            note_drop("port queue full");
            return;
        }
        if (port.peers.add(d.dst_addr_net, d.dst_port_host))
            PC_LOG_DEBUG("[UDP-RELAY] port={} peer set full, forgot the oldest peer", d.app_port);
        const uint16_t app_port = d.app_port;
        port.queue.push_back(std::move(d));
        if (!port.flushing) {
            port.flushing = true;
            asio::co_spawn(strand_, flush_port(app_port), asio::detached);
        }
    }

    asio::awaitable<void> flush_port(uint16_t app_port) {
        while (true) {
            auto it = ports_.find(app_port);
            if (it == ports_.end()) co_return;
            if (it->second.queue.empty() || !running_) {
                // Drain anything left on shutdown so the counters balance.
                for (auto& q : it->second.queue) release(q.payload.size());
                it->second.queue.clear();
                it->second.flushing = false;
                co_return;
            }
            UdpOutbound d = std::move(it->second.queue.front());
            it->second.queue.pop_front();
            const size_t bytes = d.payload.size();

            // `it` is invalid after any co_await below.
            auto socks5 = co_await socks5_mgr_.get_or_create(app_port, d.group_id);
            if (!socks5) {
                release(bytes);
                // The proxy is unreachable for this port: drop what is queued
                // rather than paying the handshake timeout once per datagram.
                if (auto again = ports_.find(app_port); again != ports_.end()) {
                    for (auto& q : again->second.queue) { release(q.payload.size()); note_drop("no proxy session"); }
                    again->second.queue.clear();
                }
                note_drop("no proxy session");
                PC_LOG_WARN("[UDP-RELAY] No SOCKS5 session for port={} group={}", app_port, d.group_id);
                continue;
            }

            auto frame = socks5_udp::encode(d.dst_addr_net, d.dst_port_host,
                                            d.payload.data(), d.payload.size());
            const auto frame_size = frame.size();
            release(bytes);
            bool sent = co_await socks5->async_send_udp(std::move(frame));
            PC_LOG_DEBUG("[UDP-RELAY] UP app_port={} dst={}:{} {} bytes sent={}",
                         app_port, ipv4_text(d.dst_addr_net), d.dst_port_host, frame_size, sent);
            if (sent) {
                upstream_count_.fetch_add(1, std::memory_order_relaxed);
                session_table_.touch(app_port);
            }
        }
    }

    // ---- Downstream: per-port async coroutine ----
    // Each app_port has its own SOCKS5 session, so responses are 1:1 with the
    // socket. The SOCKS5 header names the real responder, which becomes the
    // injected packet's source.

    asio::awaitable<void> downstream_for_session(
        uint16_t app_port, std::shared_ptr<Socks5UdpSession> session)
    {
        PC_LOG_INFO("[UDP-RELAY] Downstream started for port={}", app_port);
        uint8_t buf[65536];

        while (session->is_alive() && running_) {
            auto [n, ec] = co_await session->async_recv_udp(buf, sizeof(buf));
            if (ec) {
                if (session->is_alive() && running_)
                    PC_LOG_DEBUG("[UDP-RELAY] downstream recv error port={}: {}",
                                  app_port, ec.message());
                break;
            }
            if (n == 0) continue;

            downstream_count_.fetch_add(1, std::memory_order_relaxed);

            auto frame = socks5_udp::decode(buf, n);
            if (!frame) {
                PC_LOG_DEBUG("[UDP-RELAY] Bad SOCKS5 frame ({} bytes) port={}", n, app_port);
                continue;
            }

            auto port = ports_.find(app_port);
            if (port == ports_.end() || !port->second.peers.contains(frame->addr_net, frame->port_host)) {
                filtered_count_.fetch_add(1, std::memory_order_relaxed);
                PC_LOG_DEBUG("[UDP-RELAY] DOWN port={} from {}:{} dropped: not a peer of this socket",
                             app_port, ipv4_text(frame->addr_net), frame->port_host);
                continue;
            }

            auto s = session_table_.lookup(app_port);
            if (!s) {
                PC_LOG_DEBUG("[UDP-RELAY] No session table entry for port={}", app_port);
                continue;
            }

            PC_LOG_DEBUG("[UDP-RELAY] DOWN port={} from {}:{} {} bytes", app_port,
                         ipv4_text(frame->addr_net), frame->port_host, frame->data_len);
            session_table_.touch(app_port);
            inject_reply(*s, frame->addr_net, htons(frame->port_host), frame->data, frame->data_len);
        }

        PC_LOG_INFO("[UDP-RELAY] Downstream ended for port={}", app_port);
    }

    asio::awaitable<void> cleanup_loop() {
        while (running_) {
            cleanup_timer_.expires_after(std::chrono::seconds(30));
            auto [ec] = co_await cleanup_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
            if (ec || !running_) break;
            auto removed = socks5_mgr_.cleanup_expired();
            auto routes = session_table_.cleanup_expired();
            // Forget peer sets for sockets whose route expired.
            size_t ports = std::erase_if(ports_, [this](const auto& kv) {
                return !kv.second.flushing && kv.second.queue.empty() &&
                       !session_table_.lookup(kv.first).has_value();
            });
            if (removed || routes || ports)
                PC_LOG_INFO("[UDP-RELAY] Cleaned idle/dead sessions={} routes={} ports={}",
                            removed, routes, ports);
        }
    }

    static std::string ipv4_text(uint32_t addr_net) {
        char text[INET_ADDRSTRLEN]{};
        in_addr a{};
        a.s_addr = addr_net;
        inet_ntop(AF_INET, &a, text, sizeof(text));
        return text;
    }

    // Construct and inject a spoofed inbound UDP packet
    void inject_reply(const UdpSession& sess,
                      uint32_t src_addr_net, uint16_t src_port_net,
                      const uint8_t* payload, size_t payload_len)
    {
        if (wd_handle_ == INVALID_HANDLE_VALUE) return;

        size_t pkt_size = 20 + 8 + payload_len;
        std::vector<uint8_t> pkt(pkt_size, 0);

        auto* ip = reinterpret_cast<WINDIVERT_IPHDR*>(pkt.data());
        ip->Version   = 4;
        ip->HdrLength = 5;
        ip->Length     = htons(static_cast<uint16_t>(pkt_size));
        ip->Id         = htons(static_cast<uint16_t>(GetTickCount() & 0xFFFF));
        ip->TTL        = 64;
        ip->Protocol   = 17; // UDP
        ip->SrcAddr    = src_addr_net;
        ip->DstAddr    = sess.app_src_addr;

        auto* uh = reinterpret_cast<WINDIVERT_UDPHDR*>(pkt.data() + 20);
        uh->SrcPort = src_port_net;
        uh->DstPort = htons(sess.app_src_port);
        uh->Length  = htons(static_cast<uint16_t>(8 + payload_len));

        std::memcpy(pkt.data() + 28, payload, payload_len);

        WINDIVERT_ADDRESS wd_addr{};
        wd_addr.Outbound = FALSE;
        wd_addr.Network.IfIdx = sess.ifidx;
        wd_addr.Network.SubIfIdx = sess.subifidx;

        WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(pkt_size), &wd_addr, 0);

        UINT sent = 0;
        if (WinDivertSend(wd_handle_, pkt.data(), static_cast<UINT>(pkt_size), &sent, &wd_addr)) {
            injected_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            PC_LOG_WARN("[UDP-RELAY] Inject failed: {}", GetLastError());
        }
    }
};

} // namespace clew
