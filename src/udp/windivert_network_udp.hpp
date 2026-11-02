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
// Reply injection is done by the relay via the shared handle (WinDivertSend).
// This class exposes handle() for that purpose.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>

#include <vector>
#include <thread>
#include <atomic>
#include <cstring>
#include "core/log.hpp"

#include "rules/policy_table.hpp"
#include "udp/udp_port_tracker.hpp"
#include "udp/udp_flow.hpp"
#include "udp/udp_session_table.hpp"

namespace clew {

class windivert_network_udp {
public:
    windivert_network_udp(UdpPortTracker& tracker,
                          UdpSessionTable& session_table,
                          const PolicyPublisher& policies)
        : tracker_(tracker)
        , session_table_(session_table)
        , policies_(policies)
    {}

    ~windivert_network_udp() { close(); }

    bool open() {
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
        PC_LOG_INFO("[WD-NET-UDP] {} workers started", num_workers);
    }

    void close() {
        if (closed_) return;
        closed_ = true;
        running_ = false;
        for (auto& w : workers_) w.request_stop();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        workers_.clear();
        PC_LOG_INFO("[WD-NET-UDP] Closed (handed off={}, dropped={}, passed={})",
                     handoff_count_.load(), drop_count_.load(), pass_count_.load());
    }

    // Expose handle for reply injection from relay
    HANDLE handle() const { return handle_; }

    // Set before start(); cleared (nullptr) to stop handing off. While unset,
    // proxied datagrams are dropped rather than leaked direct.
    void set_sink(UdpOutboundSink* sink) { sink_.store(sink, std::memory_order_release); }

    uint64_t handoff_count() const { return handoff_count_; }
    uint64_t drop_count() const { return drop_count_; }
    uint64_t pass_count() const { return pass_count_; }

private:
    UdpPortTracker& tracker_;
    UdpSessionTable& session_table_;
    const PolicyPublisher& policies_;

    HANDLE handle_{INVALID_HANDLE_VALUE};
    bool closed_{false};
    std::atomic<bool> running_{false};
    std::vector<std::jthread> workers_;

    std::atomic<UdpOutboundSink*> sink_{nullptr};
    std::atomic<uint64_t> handoff_count_{0};
    std::atomic<uint64_t> drop_count_{0};
    std::atomic<uint64_t> pass_count_{0};

    void worker_loop(std::stop_token st) {
        uint8_t pkt_buf[65535];
        WINDIVERT_ADDRESS addr;
        // Per-worker view of the published policy table. The hot path below is
        // one atomic generation load; the table itself is only swapped when the
        // config actually changed.
        PolicyReader policies(policies_);

        while (!st.stop_requested() && running_) {
            UINT pkt_len = sizeof(pkt_buf);
            if (!WinDivertRecv(handle_, pkt_buf, pkt_len, &pkt_len, &addr)) {
                DWORD err = GetLastError();
                if (err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE) break;
                continue;
            }

            PWINDIVERT_IPHDR ip = nullptr;
            PWINDIVERT_UDPHDR udp = nullptr;
            PVOID payload = nullptr;
            UINT payload_len = 0;

            WinDivertHelperParsePacket(
                pkt_buf, pkt_len,
                &ip, nullptr, nullptr, nullptr, nullptr,
                nullptr, &udp, &payload, &payload_len, nullptr, nullptr);

            if (!ip || !udp) {
                WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, &addr);
                continue;
            }

            uint16_t src_port = ntohs(udp->SrcPort);

            // Check if this port is tracked for UDP proxy
            auto tracked = tracker_.get(src_port);
            if (!tracked) {
                // Not tracked — passthrough
                WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, &addr);
                pass_count_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            const auto& te = *tracked;

            const uint32_t dest_ip = ntohl(ip->DstAddr);
            const uint16_t dest_port = ntohs(udp->DstPort);
            const auto exclude_reason = policies.evaluate(te.policy_id, dest_ip, dest_port);
            if (exclude_reason != IpExcludeReason::none) {
                WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, &addr);
                pass_count_.fetch_add(1, std::memory_order_relaxed);
                PC_LOG_DEBUG("[WD-NET-UDP] Direct PID={} port={} -> {}:{} reason={}",
                             te.pid, src_port,
                             CidrRange::uint_to_ip(dest_ip), dest_port,
                             ip_exclude_reason_name(exclude_reason));
                continue;
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
    }
};

} // namespace clew
