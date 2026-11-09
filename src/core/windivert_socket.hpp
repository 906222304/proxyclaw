#pragma once

// WinDivert SOCKET layer: SNIFF + RECV_ONLY mode.
// Observes outbound TCP connect() / close() events and publishes exactly one
// decision per CONNECT into the PortTracker for the NETWORK layer.
//
// Integrates with Asio IOCP via overlapped_ptr (verified in Phase 3 PoC).
// Handler runs on strand — direct access to flat_tree side_map, no locks.
//
// WinDivert constraint: SOCKET layer requires WINDIVERT_FLAG_RECV_ONLY.
// No WinDivertSend needed — SNIFF mode auto-passes events.
//
// Decision publishing (docs/ARCHITECTURE.md, "SYN parking"):
//   - Every CONNECT produces one published decision, `proxied` or `direct`.
//     Failure paths (unknown PID that cannot be resolved, excluded
//     destination) publish `direct` — a decision, not an absence — so the
//     only way a port stays `pending` is that the event never arrived.
//   - clew's own connections are decided `direct` before any rule is
//     consulted. The SOCKET filter no longer excludes our PID: with parking,
//     an unobserved self connection would park for the full watchdog and
//     pollute the watchdog counter. A hardcoded guard replaces the filter
//     clause; a user rule like `*.exe` must never loop upstream connections.
//   - Our own re-injected SYN re-traverses ALE and yields a second CONNECT
//     (PID 4) for the same flow. It is recognised by the tracker (same remote,
//     decision younger than the TTL) and ignored.
//   - CLOSE fires at closesocket(), before the wire is done. It clears
//     `direct` / `abandoned` / `pending` slots; `proxied` slots belong to the
//     relay and are cleared at relay teardown.
//   - IPv6 (a non-IPv4-mapped remote on the IPv6 layer) is not managed:
//     the event is counted (ipv6_unmanaged) and ignored, nothing is
//     published. The NETWORK filter only diverts IPv4, so such a flow goes
//     direct. Evaluating it would read the low 32 bits of the v6 address as
//     an IPv4 destination and publish a bogus decision for its port.
//   - Every CONNECT that reaches a verdict (including IPv6 and a decision
//     rejected as late) also writes one DecisionRecord to the DecisionLog,
//     after the publish so it never delays the parked SYN. The connection
//     list reads that record instead of re-evaluating the current rules.
//   - With SYN parking switched off (no syn_parker), only `proxied`
//     decisions are published, unknown PIDs are not resolved, and the
//     tracker stays effectively two-state — exactly the pre-parking behavior.
//     Resolving without parking is worse than either: the decision lands
//     mid-flow and breaks the connection (see decide()).

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
#include <thread>
#include <unordered_map>
#include <vector>
#include "core/log.hpp"

#include "process/flat_tree.hpp"
#include "core/decision_log.hpp"
#include "core/ip_family.hpp"
#include "core/port_tracker.hpp"
#include "core/syn_parker.hpp"
#include "rules/rule_engine_v3.hpp"

namespace clew {

class windivert_socket {
public:
    // resolve_unknown_pid: called on the strand when a CONNECT event names a
    // PID the tree doesn't know yet (see process_tree_manager::resolve_pid_now).
    // Returns true once the PID is in the tree.
    // parker: the SYN-parking pool/injector, or nullptr when parking is off.
    // decisions: per-connection decision record, or nullptr (not recorded).
    windivert_socket(asio::io_context& ioc,
                     asio::strand<asio::io_context::executor_type>& strand,
                     flat_tree& tree,
                     rule_engine_v3& rules,
                     PortTracker& tracker,
                     std::function<bool(DWORD)> resolve_unknown_pid,
                     syn_parker* parker = nullptr,
                     DecisionLog* decisions = nullptr)
        : ioc_(ioc)
        , strand_(strand)
        , tree_(tree)
        , rules_(rules)
        , tracker_(tracker)
        , resolve_unknown_pid_(std::move(resolve_unknown_pid))
        , parker_(parker)
        , decisions_(decisions)
        , self_pid_(GetCurrentProcessId())
    {}

    ~windivert_socket() { close(); }

    bool open() {
        // No `processId != self` clause: see the header comment.
        const char* filter =
            "outbound and !loopback and tcp "
            "and (event == CONNECT or event == CLOSE)";

        handle_ = WinDivertOpen(filter, WINDIVERT_LAYER_SOCKET, 0,
                                WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

        if (handle_ == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[WD-SOCKET] Open failed: {}", GetLastError());
            return false;
        }

        // Register with Asio IOCP
        std::error_code ec;
        asio::use_service<asio::detail::win_iocp_io_context>(ioc_)
            .register_handle(handle_, ec);

        if (ec) {
            PC_LOG_WARN("[WD-SOCKET] IOCP register failed: {}, using blocking fallback",
                         ec.message());
            use_iocp_ = false;
        } else {
            use_iocp_ = true;
        }

        PC_LOG_INFO("[WD-SOCKET] Opened (SNIFF+RECV_ONLY, IOCP={}, parking={})",
                    use_iocp_, parker_ != nullptr);
        return true;
    }

    void start() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        running_ = true;

        if (use_iocp_) {
            async_recv();
        } else {
            // Fallback: blocking thread posts to strand
            blocking_thread_ = std::jthread([this]() { blocking_recv_loop(); });
        }
    }

    // Shutdown phase 1: WinDivertShutdown(BOTH) makes the pending/blocked
    // receive fail (the IOCP completion sees running_=false and does not
    // re-arm), then the fallback thread is joined. The handle itself is closed
    // by close() once the io_context workers are joined, so no strand handler
    // can be inside WinDivertRecvEx on a closed (possibly reused) handle.
    void stop() {
        if (stopped_) return;
        stopped_ = true;
        running_ = false;
        if (handle_ != INVALID_HANDLE_VALUE && !WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_BOTH))
            PC_LOG_WARN("[WD-SOCKET] WinDivertShutdown failed: {}", GetLastError());
        if (blocking_thread_.joinable()) blocking_thread_.join();
    }

    // Shutdown phase 2 (after the io_context workers are joined).
    void close() {
        stop();
        if (handle_ == INVALID_HANDLE_VALUE) return;
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        PC_LOG_INFO("[WD-SOCKET] Closed (connect={} close={} proxied={} self={} echo={} late={})",
                    connect_count_.load(), close_count_.load(), match_count_.load(),
                    self_direct_count_.load(), echo_count_.load(),
                    late_rejected_count_.load());
    }

    // Counters (relaxed atomics; written on the strand, read by /api/stats).
    struct counters {
        uint64_t connect_events;
        uint64_t close_events;
        uint64_t proxied_decisions;
        uint64_t direct_decisions;
        uint64_t self_direct;          // item 10 guard fired
        uint64_t echo_ignored;         // item 24: phantom CONNECT of our own injection
        uint64_t late_rejected;        // item 7: decision arrived after the watchdog released
        uint64_t late_rejected_proxied;// ...of which would have been proxied (= proxy missed)
        uint64_t close_while_pending;  // CLOSE emptied a pending slot (parked SYN dropped)
        uint64_t ipv6_unmanaged;       // IPv6 CONNECTs ignored (not proxied, go direct)
    };
    counters snapshot() const {
        return {connect_count_.load(), close_count_.load(), match_count_.load(),
                direct_count_.load(), self_direct_count_.load(), echo_count_.load(),
                late_rejected_count_.load(), late_rejected_proxied_count_.load(),
                close_while_pending_count_.load(), ipv6_unmanaged_count_.load()};
    }

private:
    asio::io_context& ioc_;
    asio::strand<asio::io_context::executor_type>& strand_;
    flat_tree& tree_;
    rule_engine_v3& rules_;
    PortTracker& tracker_;
    std::function<bool(DWORD)> resolve_unknown_pid_;
    syn_parker* parker_;
    DecisionLog* decisions_;
    const DWORD self_pid_;

    HANDLE handle_{INVALID_HANDLE_VALUE};
    bool use_iocp_{true};
    bool stopped_{false};
    std::atomic<bool> running_{false};
    std::jthread blocking_thread_;

    WINDIVERT_ADDRESS addr_{};
    UINT addr_len_{sizeof(WINDIVERT_ADDRESS)};

    std::atomic<uint64_t> connect_count_{0};
    std::atomic<uint64_t> close_count_{0};
    std::atomic<uint64_t> match_count_{0};
    std::atomic<uint64_t> direct_count_{0};
    std::atomic<uint64_t> self_direct_count_{0};
    std::atomic<uint64_t> echo_count_{0};
    std::atomic<uint64_t> late_rejected_count_{0};
    std::atomic<uint64_t> late_rejected_proxied_count_{0};
    std::atomic<uint64_t> close_while_pending_count_{0};
    std::atomic<uint64_t> ipv6_unmanaged_count_{0};

    static void bump(std::atomic<uint64_t>& c) { c.fetch_add(1, std::memory_order_relaxed); }

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
                PC_LOG_ERROR("[WD-SOCKET] RecvEx error: {}", err);
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

    // ---- Event handlers (run on strand) ----

    void on_socket_event(const WINDIVERT_ADDRESS& addr) {
        // SNIFF mode: no WinDivertSend needed, event auto-passes
        // IPv6 is out of the decision path (header comment). Its CLOSE must
        // not touch the IPv4 slot that shares the port number either.
        if (is_unmanaged_ipv6(addr.IPv6 != 0, addr.Socket.RemoteAddr)) {
            if (addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT) {
                bump(ipv6_unmanaged_count_);
                DecisionRecord rec;
                rec.pid    = addr.Socket.ProcessId;
                rec.reason = decision_reason::ipv6;
                rec.flags  = decision_flags::IPV6;
                record_decision(rec, addr);
            }
            return;
        }
        if (addr.Event == WINDIVERT_EVENT_SOCKET_CLOSE) { on_close(addr); return; }
        if (addr.Event != WINDIVERT_EVENT_SOCKET_CONNECT) return;
        on_connect(addr);
    }

    void on_connect(const WINDIVERT_ADDRESS& addr) {
        bump(connect_count_);

        const DWORD    pid         = addr.Socket.ProcessId;
        const uint16_t src_port    = static_cast<uint16_t>(addr.Socket.LocalPort);
        const uint16_t remote_port = static_cast<uint16_t>(addr.Socket.RemotePort);

        // Item 24: the CONNECT our own re-injected SYN produced. Checked first
        // so it costs neither a tree lookup nor a resolve.
        if (tracker_.is_echo(src_port, addr.Timestamp, addr.Socket.RemoteAddr, remote_port)) {
            bump(echo_count_);
            return;
        }

        TrackerEntry te{};
        std::memcpy(te.remote_addr, addr.Socket.RemoteAddr, sizeof(te.remote_addr));
        te.remote_port = remote_port;
        te.group_id    = NO_PROXY;

        DecisionRecord rec;
        rec.pid = pid;
        const slot_state decision = decide(pid, addr, te, rec);

        if (decision == slot_state::direct) {
            bump(direct_count_);
            PC_LOG_DEBUG("[WD-SOCKET] Direct PID={} port={} -> {}:{} reason={}",
                         pid, src_port, CidrRange::uint_to_ip(te.remote_addr[0]),
                         remote_port, decision_reason_name(rec.reason));
            // Parking off: keep the pre-parking two-state table (item 14).
            if (!parker_) {
                record_decision(rec, addr);
                return;
            }
        }

        const auto r = tracker_.publish(src_port, decision, te, addr.Timestamp);
        switch (r.outcome) {
        case publish_outcome::late_rejected:
            bump(late_rejected_count_);
            // The flow already left direct: that is what the record says.
            // The rejected decision survives as source / rule / LATE_PROXIED.
            rec.verdict  = decision_verdict::direct;
            rec.reason   = decision_reason::late;
            rec.group_id = DECISION_NO_GROUP;
            if (decision == slot_state::proxied) rec.flags |= decision_flags::LATE_PROXIED;
            record_decision(rec, addr);
            if (decision == slot_state::proxied) {
                bump(late_rejected_proxied_count_);
                PC_LOG_INFO("[WD-SOCKET] Late decision rejected: PID={} port={} -> {}:{} "
                            "would have been proxied (group={}); flow already released direct",
                            pid, src_port, CidrRange::uint_to_ip(te.remote_addr[0]),
                            remote_port, te.group_id);
            }
            return;
        case publish_outcome::released_parked:
            if (parker_) parker_->release(r.parked, src_port, decision);
            break;
        case publish_outcome::stored:
            break;
        }
        // After the publish (and the parked SYN's hand-off): off the
        // SYN's critical path.
        record_decision(rec, addr);

        if (decision == slot_state::proxied) {
            bump(match_count_);
            PC_LOG_DEBUG("[WD-SOCKET] Match PID={} port={} -> {}:{} group={}{}",
                         pid, src_port, CidrRange::uint_to_ip(te.remote_addr[0]),
                         remote_port, te.group_id,
                         r.outcome == publish_outcome::released_parked ? " (parked)" : "");
        }
    }

    // Stamp the record with the event's key and append it. O(1), no
    // allocation (DecisionLog::record).
    void record_decision(DecisionRecord& rec, const WINDIVERT_ADDRESS& addr) {
        if (!decisions_) return;
        rec.proto       = decision_proto::tcp;
        rec.local_port  = static_cast<uint16_t>(addr.Socket.LocalPort);
        rec.remote_port = static_cast<uint16_t>(addr.Socket.RemotePort);
        if (rec.flags & decision_flags::IPV6) {
            std::memcpy(rec.remote_addr, addr.Socket.RemoteAddr, sizeof(rec.remote_addr));
        } else {
            rec.remote_addr[0] = addr.Socket.RemoteAddr[0];   // IPv4(-mapped): word [0] only
        }
        rec.config_version = rules_.config_version();
        rec.at_ms          = decision_now_ms();
        decisions_->record(rec);
    }

    // The decision for one CONNECT. Fills te.group_id when proxied, and
    // rec's verdict / reason / source / rule / group / psn.
    slot_state decide(DWORD pid, const WINDIVERT_ADDRESS& addr, TrackerEntry& te, DecisionRecord& rec) {
        // Item 10: never proxy ourselves, whatever the rules say. Our upstream
        // connections (relay -> SOCKS5 server, group test, DNS forwarder) are
        // the flows a broad rule would otherwise loop back into the acceptor.
        if (pid == self_pid_) {
            bump(self_direct_count_);
            rec.reason = decision_reason::self;
            return slot_state::direct;
        }

        // Make sure the tree holds *this* process (strand-safe, no locks).
        // Unknown PID: nearly always a process younger than the ~1-2s ETW
        // ProcessStart latency; it is connecting right now, so it is alive and
        // can be resolved on the spot. Known PID: verified against the live
        // PSN, because ETW STOP is just as late and a recycled PID would
        // otherwise inherit its dead predecessor's classification.
        //
        // Only with parking. Without it the SYN is already on the wire, and a
        // decision published ~100us later lands mid-flow: the NETWORK layer
        // starts reflecting an established direct connection and the TLS
        // handshake times out (measured 20/20 with resolve on, parking off).
        // The kill switch therefore means the pre-parking path: known PIDs
        // only, no resolve, no identity check.
        if (parker_ && resolve_unknown_pid_ && !resolve_unknown_pid_(pid)) {
            rec.reason = decision_reason::unknown_pid;
            return slot_state::direct;
        }
        // The resolve may append to the tree, which can reallocate entries_,
        // so look up after it rather than reusing an earlier index.
        const uint32_t idx = tree_.find_by_pid(pid);
        if (idx == INVALID_IDX) {
            rec.reason = decision_reason::unknown_pid;
            return slot_state::direct;
        }

        const auto& entry = tree_.at(idx);
        rec.psn = entry.psn;
        if (!entry.alive || !entry.is_proxied()) {
            rec.reason = decision_reason::not_proxied;
            return slot_state::direct;
        }
        const auto origin = rules_.origin_of(entry);
        rec.source    = origin.source;
        rec.policy_id = origin.policy_id;

        const uint32_t dest_ip = addr.Socket.RemoteAddr[0];
        const auto dest_port = static_cast<uint16_t>(addr.Socket.RemotePort);
        const auto exclude_reason =
            rules_.route_reason(tree_, pid, /*is_udp=*/false, dest_ip, dest_port);
        if (exclude_reason != IpExcludeReason::none) {
            rec.reason = to_decision_reason(exclude_reason);
            return slot_state::direct;
        }

        te.group_id  = entry.group_id;
        rec.verdict  = decision_verdict::proxied;
        rec.reason   = decision_reason::none;
        rec.group_id = entry.group_id;
        return slot_state::proxied;
    }

    void on_close(const WINDIVERT_ADDRESS& addr) {
        bump(close_count_);
        const uint16_t src_port = static_cast<uint16_t>(addr.Socket.LocalPort);
        if (auto idx = tracker_.on_close(src_port, addr.Timestamp)) {
            // The flow closed before its SYN was ever released: the socket is
            // gone, the packet is dropped, the pool slot goes back.
            bump(close_while_pending_count_);
            if (parker_) parker_->free_slot(*idx);
        }
    }
};

} // namespace clew
