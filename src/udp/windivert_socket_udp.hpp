#pragma once

// WinDivert SOCKET layer for UDP: SNIFF + RECV_ONLY mode.
// Observes UDP bind() and connect() events, writes matching entries
// to UdpPortTracker for UDP NETWORK layer to intercept.
//
// Independent from TCP SOCKET layer — separate handle, filter, tracker.
// Same IOCP/blocking fallback pattern as TCP version.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <windivert.h>

#define ASIO_STANDALONE
#include <asio.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <format>
#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include "core/decision_log.hpp"
#include "core/ip_family.hpp"
#include "core/log.hpp"

#include "process/flat_tree.hpp"
#include "rules/rule_engine_v3.hpp"
#include "udp/udp_port_tracker.hpp"

namespace clew {

class windivert_socket_udp {
public:
    // resolve_unknown_pid: see windivert_socket. Same fallback, same contract.
    windivert_socket_udp(asio::io_context& ioc,
                         asio::strand<asio::io_context::executor_type>& strand,
                         flat_tree& tree,
                         rule_engine_v3& rules,
                         UdpPortTracker& tracker,
                         std::function<bool(DWORD)> resolve_unknown_pid)
        : ioc_(ioc)
        , strand_(strand)
        , tree_(tree)
        , rules_(rules)
        , tracker_(tracker)
        , resolve_unknown_pid_(std::move(resolve_unknown_pid))
    {}

    ~windivert_socket_udp() { close(); }

    bool open() {
        DWORD self_pid = GetCurrentProcessId();

        // Our own sockets are observed too (and decided direct below), so
        // the NETWORK layer's first-packet parking never holds the relay's
        // datagrams waiting for a decision that would never come.
        self_pid_ = self_pid;
        auto filter = std::string("udp and !loopback");

        handle_ = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_SOCKET, 0,
                                WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

        if (handle_ == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[WD-SOCKET-UDP] Open failed: {}", GetLastError());
            return false;
        }

        // Register with Asio IOCP
        std::error_code ec;
        asio::use_service<asio::detail::win_iocp_io_context>(ioc_)
            .register_handle(handle_, ec);

        if (ec) {
            PC_LOG_WARN("[WD-SOCKET-UDP] IOCP register failed: {}, using blocking fallback",
                         ec.message());
            use_iocp_ = false;
        } else {
            use_iocp_ = true;
        }

        PC_LOG_INFO("[WD-SOCKET-UDP] Opened (SNIFF+RECV_ONLY, IOCP={})", use_iocp_);
        return true;
    }

    void start() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        running_ = true;

        if (use_iocp_) {
            async_recv();
        } else {
            blocking_thread_ = std::jthread([this]() { blocking_recv_loop(); });
        }
    }

    // Shutdown phase 1: see windivert_socket::stop().
    void stop() {
        if (stopped_) return;
        stopped_ = true;
        running_ = false;
        if (handle_ != INVALID_HANDLE_VALUE && !WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_BOTH))
            PC_LOG_WARN("[WD-SOCKET-UDP] WinDivertShutdown failed: {}", GetLastError());
        if (blocking_thread_.joinable()) blocking_thread_.join();
    }

    // Shutdown phase 2 (after the io_context workers are joined).
    void close() {
        if (closed_) return;
        closed_ = true;
        stop();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        PC_LOG_INFO("[WD-SOCKET-UDP] Closed (events={}, matches={})", event_count_, match_count_);
    }

    // Called on the strand after a port's decision is stored or cleared, so
    // datagrams the NETWORK layer parked for it are sent.
    void set_decision_listener(std::function<void(uint16_t)> fn) { on_decided_ = std::move(fn); }

    // Per-connection decision record (one per port-level decision, keyed by
    // local port). Set before start(); nullptr = not recorded.
    void set_decision_log(DecisionLog* log) { decisions_ = log; }

    uint64_t event_count() const { return event_count_; }
    uint64_t match_count() const { return match_count_; }
    // IPv6 CONNECTs ignored (not proxied). Written on the strand, read by /api/stats.
    uint64_t ipv6_unmanaged_count() const { return ipv6_unmanaged_count_.load(std::memory_order_relaxed); }

    // ipv6.mode = block flag (shared with the NETWORK workers). Set before start().
    void set_ipv6_block(const std::atomic<bool>* block) { ipv6_block_ = block; }

private:
    asio::io_context& ioc_;
    asio::strand<asio::io_context::executor_type>& strand_;
    flat_tree& tree_;
    rule_engine_v3& rules_;
    UdpPortTracker& tracker_;
    std::function<bool(DWORD)> resolve_unknown_pid_;
    std::function<void(uint16_t)> on_decided_;
    DecisionLog* decisions_{nullptr};
    DWORD self_pid_{0};

    HANDLE handle_{INVALID_HANDLE_VALUE};
    bool use_iocp_{true};
    bool closed_{false};
    bool stopped_{false};
    std::atomic<bool> running_{false};
    std::jthread blocking_thread_;

    WINDIVERT_ADDRESS addr_{};
    UINT addr_len_{sizeof(WINDIVERT_ADDRESS)};

    uint64_t event_count_{0};
    uint64_t match_count_{0};
    std::atomic<uint64_t> ipv6_unmanaged_count_{0};
    const std::atomic<bool>* ipv6_block_{nullptr};

    // ---- Asio IOCP async path ----

    void async_recv() {
        if (!running_) return;

        asio::windows::overlapped_ptr op{
            strand_,
            [this](std::error_code ec, std::size_t) {
                if (!ec && running_) {
                    on_socket_event(addr_);
                    async_recv();
                }
            }
        };

        BOOL ok = WinDivertRecvEx(
            handle_, nullptr, 0, nullptr, 0,
            &addr_, &addr_len_, op.get());

        DWORD err = GetLastError();
        if (!ok && err == ERROR_IO_PENDING) {
            op.release();
        } else if (ok) {
            op.complete(std::error_code{}, 0);
        } else {
            if (running_)
                PC_LOG_ERROR("[WD-SOCKET-UDP] RecvEx error: {}", err);
        }
    }

    // ---- Blocking fallback path ----

    void blocking_recv_loop() {
        WINDIVERT_ADDRESS addr;
        while (running_) {
            UINT recv_len = 0;
            if (!WinDivertRecv(handle_, nullptr, 0, &recv_len, &addr)) {
                DWORD err = GetLastError();
                if (err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));  // no hot spin
                continue;
            }
            asio::post(strand_, [this, addr]() {
                on_socket_event(addr);
            });
        }
    }

    // ---- Event handler (runs on strand) ----

    void notify(uint16_t port) {
        if (on_decided_) on_decided_(port);
    }

    // After the tracker write and the parked-datagram release, so the record
    // never delays a datagram. BIND carries no remote; CONNECT names one.
    void record_decision(DecisionRecord& rec, const WINDIVERT_ADDRESS& addr) {
        if (!decisions_) return;
        rec.proto      = decision_proto::udp;
        rec.pid        = addr.Socket.ProcessId;
        rec.local_port = static_cast<uint16_t>(addr.Socket.LocalPort);
        if (addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT) {
            if (rec.flags & decision_flags::IPV6)
                std::memcpy(rec.remote_addr, addr.Socket.RemoteAddr, sizeof(rec.remote_addr));
            else
                rec.remote_addr[0] = addr.Socket.RemoteAddr[0];
            rec.remote_port = static_cast<uint16_t>(addr.Socket.RemotePort);
        }
        rec.config_version = rules_.config_version();
        rec.at_ms          = decision_now_ms();
        decisions_->record(rec);
    }

    void decide_direct(uint16_t port, const WINDIVERT_ADDRESS& addr, decision_reason why,
                       const process_entry* entry = nullptr) {
        tracker_.put_direct(port);
        notify(port);
        DecisionRecord rec;
        rec.reason = why;
        if (entry) {
            rec.psn = entry->psn;
            const auto origin = rules_.origin_of(*entry);
            rec.source    = origin.source;
            rec.policy_id = origin.policy_id;
        }
        record_decision(rec, addr);
    }

    void log_excluded_connect(const WINDIVERT_ADDRESS& addr, DWORD pid, uint16_t src_port) {
        const uint32_t dest_ip = addr.Socket.RemoteAddr[0];
        const auto dest_port = static_cast<uint16_t>(addr.Socket.RemotePort);
        const auto reason = rules_.ip_exclude_reason(tree_, pid, dest_ip, dest_port);
        if (reason != IpExcludeReason::none) {
            PC_LOG_DEBUG("[WD-SOCKET-UDP] Direct PID={} port={} -> {}:{} reason={} (per packet)",
                          pid, src_port, CidrRange::uint_to_ip(dest_ip), dest_port,
                          ip_exclude_reason_name(reason));
        }
    }

    void on_socket_event(const WINDIVERT_ADDRESS& addr) {
        // Accept both BIND and CONNECT for UDP
        if (addr.Event != WINDIVERT_EVENT_SOCKET_BIND &&
            addr.Event != WINDIVERT_EVENT_SOCKET_CONNECT) {
            // Handle CLOSE: clear tracker entry
            if (addr.Event == WINDIVERT_EVENT_SOCKET_CLOSE) {
                uint16_t port = static_cast<uint16_t>(addr.Socket.LocalPort);
                tracker_.clear(port);
                notify(port);   // anything still parked for a closed socket goes direct
            }
            return;
        }

        // A CONNECT to a real IPv6 remote is not managed: the NETWORK filter
        // only diverts IPv4, and the per-destination checks read the remote
        // as IPv4. BIND carries no remote and stays a per-port decision, since
        // a dual-stack socket bound on the IPv6 layer may still send IPv4.
        // With ipv6.mode = block the NETWORK workers drop a proxied port's
        // IPv6 datagrams (per packet, like the IPv4 excludes); the record
        // says so when the port is proxied.
        if (addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT &&
            is_unmanaged_ipv6(addr.IPv6 != 0, addr.Socket.RemoteAddr)) {
            ipv6_unmanaged_count_.fetch_add(1, std::memory_order_relaxed);
            DecisionRecord rec;
            rec.flags  = decision_flags::IPV6;
            const auto port = static_cast<uint16_t>(addr.Socket.LocalPort);
            if (!tracker_.is_active(port)) {
                rec.reason = decision_reason::not_proxied;
            } else if (ipv6_block_ && ipv6_block_->load(std::memory_order_relaxed)) {
                rec.reason = decision_reason::ipv6_blocked;
            } else {
                rec.reason = decision_reason::ipv6;
            }
            record_decision(rec, addr);
            return;
        }

        event_count_++;

        const DWORD pid = addr.Socket.ProcessId;
        const uint16_t src_port = static_cast<uint16_t>(addr.Socket.LocalPort);
        const bool is_connect = (addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT);

        // A CONNECT on a port already proxied (from its BIND) carries nothing
        // new: per-destination excludes are evaluated per packet by the
        // NETWORK workers. A port decided direct is re-evaluated, as before,
        // so a rule enabled after the socket was bound still takes effect.
        if (is_connect && tracker_.is_active(src_port)) {
            log_excluded_connect(addr, pid, src_port);
            return;
        }
        if (pid == self_pid_) { decide_direct(src_port, addr, decision_reason::self); return; }

        // Resolve before the rule gate, not after: should_proxy_protocol looks
        // the PID up in the tree itself and answers false for anything it
        // doesn't know, so a process younger than the ETW ProcessStart latency
        // would be dropped here before ever reaching the lookup below. Called
        // for known PIDs too: it verifies the entry against the live PSN, so
        // a PID recycled before its ETW STOP arrived is re-resolved.
        if (resolve_unknown_pid_ && !resolve_unknown_pid_(pid)) {
            decide_direct(src_port, addr, decision_reason::unknown_pid);
            return;
        }

        // Lookup group_id from flat_tree
        uint32_t idx = tree_.find_by_pid(pid);
        if (idx == INVALID_IDX) { decide_direct(src_port, addr, decision_reason::unknown_pid); return; }
        const auto& entry = tree_.at(idx);

        // Check if this PID should be proxied for UDP protocol
        if (!rules_.should_proxy_protocol(tree_, pid, "udp")) {
            const bool proxied_process = entry.alive && entry.is_proxied();
            decide_direct(src_port, addr,
                          proxied_process ? decision_reason::rule_protocol
                                          : decision_reason::not_proxied,
                          proxied_process ? &entry : nullptr);
            return;
        }

        // WFP raises a CONNECT event for an explicit connect() AND for each
        // new remote an unconnected socket sendto()s, so a CONNECT names one
        // destination, not the socket's only one. Clearing the slot on an
        // excluded destination would also stop proxying every other
        // destination of that socket (seen in CI: DNS to 1.1.1.1 went direct
        // after the same socket sent to an excluded 8.8.8.8). Excludes are
        // evaluated per packet by the NETWORK workers.
        if (is_connect) log_excluded_connect(addr, pid, src_port);

        // Write to UdpPortTracker (release semantics for NETWORK workers)
        UdpTrackerEntry te{};
        te.group_id = entry.group_id;
        te.pid = pid;
        te.policy_id = rules_.policy_id_for(tree_, pid);

        tracker_.put(src_port, te);
        match_count_++;
        notify(src_port);

        DecisionRecord rec;
        rec.verdict  = decision_verdict::proxied;
        rec.group_id = entry.group_id;
        rec.psn      = entry.psn;
        const auto origin = rules_.origin_of(entry);
        rec.source    = origin.source;
        rec.policy_id = origin.policy_id;
        record_decision(rec, addr);

        PC_LOG_DEBUG("[WD-SOCKET-UDP] Match PID={} port={} event={} group={} policy={}",
                      pid, src_port, is_connect ? "CONNECT" : "BIND",
                      te.group_id, te.policy_id);
    }
};

} // namespace clew
