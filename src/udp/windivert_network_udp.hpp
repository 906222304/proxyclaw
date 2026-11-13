#pragma once

// WinDivert NETWORK layer for UDP: intercept + hand off + inject.
// Independent from TCP NETWORK layer — separate handle, filter, workers.
//
// Forward path (app -> relay):
//   Outbound UDP from a tracked port that the policy proxies is consumed here:
//   its payload and its own destination go to the relay (UdpOutboundSink) and
//   the original packet is not re-injected. Carrying the destination with each
//   datagram keeps a socket that talks to several peers correct.
//   UdpSessionTable keeps the app-side metadata (address, interface, last
//   destination for the UI) the relay needs to inject replies.
//
// First packet: a datagram from a port with no decision yet (its BIND event
// has not been handled on the strand) is parked, not sent direct. release()
// sends it once the SOCKET layer decides; a watchdog sends it direct after
// the deadline and pins the port direct (udp_first_packet.hpp).
//
// Reply injection is done by the relay via the shared handle (WinDivertSend).
// This class exposes handle() for that purpose.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cstring>
#include "core/decision_log.hpp"
#include "core/log.hpp"
#include "core/ip_family.hpp"

#include "rules/policy_table.hpp"
#include "udp/udp_port_tracker.hpp"
#include "udp/udp_first_packet.hpp"
#include "udp/udp_flow.hpp"
#include "udp/udp_session_table.hpp"

namespace clew {

class windivert_network_udp {
public:
    // park_deadline 0 disables first-packet parking (pre-v0.11 behavior).
    windivert_network_udp(UdpPortTracker& tracker,
                          UdpSessionTable& session_table,
                          const PolicyPublisher& policies,
                          std::chrono::milliseconds park_deadline = std::chrono::milliseconds{20},
                          UdpParkingLimits park_limits = {})
        : tracker_(tracker)
        , session_table_(session_table)
        , policies_(policies)
        , park_deadline_(park_deadline)
        , parker_(park_limits)
        , release_policies_(policies)
    {}

    ~windivert_network_udp() { close(); }

    bool open() {
        // IPv4 and IPv6. IPv6 is not proxied: its datagrams pass unchanged,
        // except a proxied port's under ipv6.mode = block, which are dropped
        // so the application falls back to IPv4 (QUIC to TCP).
        const char* filter = "udp and outbound and !loopback";

        handle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle_ == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[WD-NET-UDP] Open failed: {}", GetLastError());
            return false;
        }

        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, 2000);
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);

        PC_LOG_INFO("[WD-NET-UDP] Opened (filter: {})", filter);
        return true;
    }

    void start(int num_workers = 2) {
        running_ = true;
        for (int i = 0; i < num_workers; i++) {
            workers_.emplace_back([this](std::stop_token st) {
                worker_loop(st);
            });
        }
        if (park_deadline_.count() > 0) {
            watchdog_ = std::jthread([this](std::stop_token st) { watchdog_loop(st); });
        }
        PC_LOG_INFO("[WD-NET-UDP] {} workers started (first-packet parking {})", num_workers,
                    park_deadline_.count() > 0 ? std::to_string(park_deadline_.count()) + " ms" : std::string("off"));
    }

    // Shutdown phase 1: WinDivertShutdown(RECV), join the workers (they drain
    // the queue and exit on ERROR_NO_DATA), then stop the park watchdog. The
    // handle stays open for sends (watchdog / strand release() / UdpRelay
    // reply injection) until close(). Idempotent.
    void stop_workers() {
        if (workers_stopped_) return;
        workers_stopped_ = true;
        if (handle_ != INVALID_HANDLE_VALUE && !workers_.empty()) {
            if (!WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_RECV)) {
                PC_LOG_ERROR("[WD-NET-UDP] WinDivertShutdown failed: {}", GetLastError());
                running_ = false;
                for (auto& w : workers_) w.request_stop();
                WinDivertClose(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
        workers_.clear();
        running_ = false;
        if (watchdog_.joinable()) { watchdog_.request_stop(); watchdog_.join(); }
    }

    // Shutdown phase 2: close the handle, after every sender (relay, strand)
    // has stopped, i.e. after the io_context workers are joined.
    void close() {
        if (closed_) return;
        closed_ = true;
        stop_workers();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        PC_LOG_INFO("[WD-NET-UDP] Closed (handed off={}, dropped={}, passed={}, parked={}, "
                    "released by decision={}, by watchdog={}, park full={})",
                     handoff_count_.load(), drop_count_.load(), pass_count_.load(),
                     park_count_.load(), released_decision_.load(), released_watchdog_.load(),
                     park_full_.load());
    }

    // Per-connection decision record: a port the park watchdog pins direct
    // is recorded as `watchdog`. Set before start().
    void set_decision_log(DecisionLog* log) { decisions_ = log; }

    // ipv6.mode = block flag (runtime). Unset: IPv6 always passes.
    void set_ipv6_block(const std::atomic<bool>* block) { ipv6_block_ = block; }
    uint64_t ipv6_blocked_count() const { return ipv6_blocked_.load(std::memory_order_relaxed); }

    // Expose handle for reply injection from relay
    HANDLE handle() const { return handle_; }

    // Set before start(); cleared (nullptr) to stop handing off. While unset,
    // proxied datagrams are dropped rather than leaked direct.
    void set_sink(UdpOutboundSink* sink) { sink_.store(sink, std::memory_order_release); }

    // Called on the strand right after the SOCKET layer stored a decision for
    // `port` (or cleared it on CLOSE): sends what was parked for it.
    void release(uint16_t port) {
        if (park_deadline_.count() == 0) return;
        auto packets = parker_.take(port);
        if (packets.empty()) return;
        released_decision_.fetch_add(packets.size(), std::memory_order_relaxed);
        for (auto& p : packets) dispatch_decided(release_policies_, p);
    }

    uint64_t park_count() const { return park_count_; }
    uint64_t handoff_count() const { return handoff_count_; }
    uint64_t drop_count() const { return drop_count_; }
    uint64_t pass_count() const { return pass_count_; }

private:
    UdpPortTracker& tracker_;
    UdpSessionTable& session_table_;
    const PolicyPublisher& policies_;

    HANDLE handle_{INVALID_HANDLE_VALUE};
    bool closed_{false};
    bool workers_stopped_{false};
    std::atomic<bool> running_{false};
    std::vector<std::jthread> workers_;

    std::atomic<UdpOutboundSink*> sink_{nullptr};
    DecisionLog* decisions_{nullptr};
    const std::atomic<bool>* ipv6_block_{nullptr};
    std::atomic<uint64_t> ipv6_blocked_{0};
    std::atomic<uint64_t> handoff_count_{0};
    std::atomic<uint64_t> drop_count_{0};
    std::atomic<uint64_t> pass_count_{0};
    std::atomic<uint64_t> park_count_{0};
    std::atomic<uint64_t> released_decision_{0};
    std::atomic<uint64_t> released_watchdog_{0};
    std::atomic<uint64_t> park_full_{0};

    struct parked_packet {
        std::vector<uint8_t> bytes;
        WINDIVERT_ADDRESS    addr{};
    };
    std::chrono::milliseconds park_deadline_;
    udp_first_packet_parker<parked_packet> parker_;
    PolicyReader release_policies_;   // strand only (release())
    std::jthread watchdog_;

    void send_direct(const uint8_t* pkt, UINT len, const WINDIVERT_ADDRESS& addr) {
        WinDivertSend(handle_, pkt, len, nullptr, &addr);
        pass_count_.fetch_add(1, std::memory_order_relaxed);
    }

    // A parked datagram whose port now has a decision (or was closed).
    void dispatch_decided(PolicyReader& policies, parked_packet& p) {
        handle_packet(policies, p.bytes.data(), static_cast<UINT>(p.bytes.size()), p.addr,
                      /*may_park=*/false);
    }

    void watchdog_loop(std::stop_token st) {
        PolicyReader policies(policies_);
        const auto tick = std::max(std::chrono::milliseconds{1}, park_deadline_ / 4);
        while (!st.stop_requested() && running_) {
            std::this_thread::sleep_for(tick);
            auto due = parker_.expire(std::chrono::steady_clock::now(), park_deadline_);
            for (auto& [port, packets] : due) {
                // No BIND seen in time (socket older than ProxyClaw, or the
                // strand is backed up): pin direct so the port stops parking.
                // If a decision landed meanwhile, the pin loses and the
                // packets follow that decision instead.
                if (tracker_.pin_direct_if_empty(port) && decisions_) {
                    DecisionRecord rec;
                    rec.proto      = decision_proto::udp;
                    rec.local_port = port;
                    rec.verdict    = decision_verdict::direct;
                    rec.reason     = decision_reason::watchdog;
                    rec.at_ms      = decision_now_ms();
                    decisions_->record(rec);
                }
                released_watchdog_.fetch_add(packets.size(), std::memory_order_relaxed);
                for (auto& p : packets) dispatch_decided(policies, p);
            }
        }
    }

    void worker_loop(std::stop_token st) {
        uint8_t pkt_buf[65535];
        WINDIVERT_ADDRESS addr;
        // Per-worker view of the published policy table. The hot path below is
        // one atomic generation load; the table itself is only swapped when the
        // config actually changed.
        PolicyReader policies(policies_);

        uint32_t recv_errors = 0;
        // Exits on ERROR_NO_DATA: RECV shut down and queue drained.
        while (!st.stop_requested()) {
            UINT pkt_len = sizeof(pkt_buf);
            if (!WinDivertRecv(handle_, pkt_buf, pkt_len, &pkt_len, &addr)) {
                DWORD err = GetLastError();
                if (err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE) break;
                if ((recv_errors++ & 1023) == 0)
                    PC_LOG_WARN("[WD-NET-UDP] Recv error {} (x{})", err, recv_errors);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }

            handle_packet(policies, pkt_buf, pkt_len, addr, /*may_park=*/true);
        }
    }

    // An IPv6 datagram: never proxied. Dropped when its port is proxied, the
    // rule covers this destination port and the destination is not
    // local-scope (ipv6.mode = block); otherwise sent unchanged.
    void handle_ipv6(PolicyReader& policies, const uint8_t* pkt_buf, UINT pkt_len,
                     const WINDIVERT_ADDRESS& addr, const WINDIVERT_IPV6HDR& ip6,
                     uint16_t src_port, uint16_t dest_port) {
        const auto tracked = tracker_.get(src_port);
        if (!tracked || !ipv6_block_ || !ipv6_block_->load(std::memory_order_relaxed)) {
            send_direct(pkt_buf, pkt_len, addr);
            return;
        }
        uint8_t dst[16];
        std::memcpy(dst, ip6.DstAddr, sizeof(dst));   // network order
        if (policies.evaluate_v6(tracked->policy_id, is_local_scope_ipv6(dst), dest_port)
                != IpExcludeReason::none) {
            send_direct(pkt_buf, pkt_len, addr);
            return;
        }
        ipv6_blocked_.fetch_add(1, std::memory_order_relaxed);
    }

    void handle_packet(PolicyReader& policies, uint8_t* pkt_buf, UINT pkt_len,
                       const WINDIVERT_ADDRESS& addr, bool may_park) {
        PWINDIVERT_IPHDR ip = nullptr;
        PWINDIVERT_IPV6HDR ip6 = nullptr;
        PWINDIVERT_UDPHDR udp = nullptr;
        PVOID payload = nullptr;
        UINT payload_len = 0;

        WinDivertHelperParsePacket(
            pkt_buf, pkt_len,
            &ip, &ip6, nullptr, nullptr, nullptr,
            nullptr, &udp, &payload, &payload_len, nullptr, nullptr);

        if ((!ip && !ip6) || !udp) {
            WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, &addr);
            return;
        }

        uint16_t src_port = ntohs(udp->SrcPort);

        if (may_park && park_deadline_.count() > 0 &&
            tracker_.state(src_port) == udp_slot_state::empty) {
            parked_packet p{std::vector<uint8_t>(pkt_buf, pkt_buf + pkt_len), addr};
            const auto r = parker_.park(src_port, p, std::chrono::steady_clock::now(),
                                        [&] { return !tracker_.decided(src_port); });
            if (r == udp_park_result::parked) {
                park_count_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (r == udp_park_result::full) {
                park_full_.fetch_add(1, std::memory_order_relaxed);
                send_direct(pkt_buf, pkt_len, addr);
                return;
            }
            // decided meanwhile: fall through and follow the decision
        }

        if (ip6) { handle_ipv6(policies, pkt_buf, pkt_len, addr, *ip6, src_port, ntohs(udp->DstPort)); return; }

        // Check if this port is tracked for UDP proxy
        auto tracked = tracker_.get(src_port);
        if (!tracked) {
            // Not tracked — passthrough
            send_direct(pkt_buf, pkt_len, addr);
            return;
        }
        const auto& te = *tracked;

        const uint32_t dest_ip = ntohl(ip->DstAddr);
        const uint16_t dest_port = ntohs(udp->DstPort);
        const auto exclude_reason = policies.evaluate(te.policy_id, dest_ip, dest_port);
        if (exclude_reason != IpExcludeReason::none) {
            send_direct(pkt_buf, pkt_len, addr);
            PC_LOG_DEBUG("[WD-NET-UDP] Direct PID={} port={} -> {}:{} reason={}",
                         te.pid, src_port,
                         CidrRange::uint_to_ip(dest_ip), dest_port,
                         ip_exclude_reason_name(exclude_reason));
            return;
        }

        // App-side metadata for reply injection; orig_dst_* is the most
        // recent destination, shown in the connection list.
        UdpSession session{};
        session.orig_dst_addr = ip->DstAddr;
        session.orig_dst_port = udp->DstPort;
        session.app_src_addr  = ip->SrcAddr;
        session.app_src_port  = src_port;
        session.pid           = te.pid;
        session.group_id      = te.group_id;
        session.ifidx         = addr.Network.IfIdx;
        session.subifidx      = addr.Network.SubIfIdx;
        session_table_.upsert(src_port, session);

        // Hand the datagram, with its own destination, to the relay. The
        // original packet is consumed (not re-injected).
        UdpOutbound out;
        out.app_port      = src_port;
        out.group_id      = te.group_id;
        out.dst_addr_net  = ip->DstAddr;
        out.dst_port_host = dest_port;
        if (payload && payload_len)
            out.payload.assign(static_cast<const uint8_t*>(payload),
                               static_cast<const uint8_t*>(payload) + payload_len);
        auto* sink = sink_.load(std::memory_order_acquire);
        if (sink && sink->submit(std::move(out))) {
            handoff_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            drop_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }
};

} // namespace clew
