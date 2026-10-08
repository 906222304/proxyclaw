#pragma once

// WinDivert NETWORK layer: Reflection mode with batch I/O.
// Redirects matched TCP traffic to local listener using addr swap + inbound reinject.
// Pattern matches official WinDivert streamdump.exe example.
//
// Design (from architecture_redesign_v3.md §3.5):
//   - 2-4 dedicated blocking worker threads (NOT Asio IOCP)
//   - Batch RecvEx/SendEx for throughput
//   - Hot path: O(1) PortTracker lookup → passthrough if no match
//   - Cold path: NAT rewrite + checksum recalc
//   - All non-loopback outbound TCP is captured; filter: "outbound and tcp and !loopback"
//
// Reflection (方案 B):
//   Forward: swap(SrcAddr, DstAddr), DstPort=redirect_port, Outbound=0 → inbound reinject
//   Reverse: proxy reply is also outbound non-loopback, swap back, Outbound=0 → inbound reinject

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

#include "core/port_tracker.hpp"
#include "core/syn_parker.hpp"

namespace clew {

class windivert_network {
public:
    // parker: SYN-parking pool/injector, or nullptr to keep the pre-parking
    // behavior (every SYN without a decision passes through unchanged).
    windivert_network(PortTracker& tracker, uint16_t redirect_port, syn_parker* parker = nullptr)
        : tracker_(tracker)
        , redirect_port_(redirect_port)
        , parker_(parker)
        , ttl_ticks_(tracker.ttl_ticks())
    {}

    HANDLE handle() const { return handle_; }

    ~windivert_network() { close(); }

    bool open() {
        const char* filter = "outbound and tcp and !loopback";

        handle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle_ == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[WD-NETWORK] Open failed: {}", GetLastError());
            return false;
        }

        // Tune queue params for high throughput
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, 2000);
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);

        PC_LOG_INFO("[WD-NETWORK] Opened (Reflection, filter: {})", filter);
        return true;
    }

    void start(int num_workers = 2) {
        running_ = true;
        for (int i = 0; i < num_workers; i++) {
            workers_.emplace_back([this](std::stop_token st) {
                worker_loop(st);
            });
        }
        PC_LOG_INFO("[WD-NETWORK] {} worker threads started", num_workers);
    }

    void close() {
        running_ = false;
        for (auto& w : workers_) w.request_stop();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        workers_.clear();
        PC_LOG_INFO("[WD-NETWORK] Closed");
    }

    uint64_t nat_count() const { return nat_count_; }
    uint64_t pass_count() const { return pass_count_; }

private:
    PortTracker& tracker_;
    uint16_t redirect_port_;
    syn_parker* parker_;
    int64_t ttl_ticks_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    std::atomic<bool> running_{false};
    std::vector<std::jthread> workers_;

    std::atomic<uint64_t> nat_count_{0};
    std::atomic<uint64_t> pass_count_{0};

    void passthrough(uint8_t* pkt_buf, UINT pkt_len, WINDIVERT_ADDRESS* addr) {
        WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, addr);
        pass_count_.fetch_add(1, std::memory_order_relaxed);
    }

    // Act on a decided slot state for this SYN.
    void act(slot_state st, uint8_t* pkt_buf, UINT pkt_len, WINDIVERT_ADDRESS* addr) {
        if (st == slot_state::proxied) {
            reflect_outbound_packet(handle_, pkt_buf, pkt_len, addr, redirect_port_);
            nat_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            passthrough(pkt_buf, pkt_len, addr);
        }
    }

    // Outbound SYN (no ACK) with SYN parking on. Everything here is the
    // NETWORK side of docs/ARCHITECTURE.md "SYN parking".
    void handle_syn(uint8_t* pkt_buf, UINT pkt_len, uint32_t seq,
                    uint16_t src_port, WINDIVERT_ADDRESS* addr) {
        auto v = tracker_.load(src_port);
        auto st = v.state();

        if (st == slot_state::proxied || st == slot_state::direct || st == slot_state::abandoned) {
            // Item 21: a decision is only ours if it is younger than the TTL,
            // measured on the kernel clock at both ends. Older means a
            // leftover from a previous flow on this port: treat the slot as
            // empty and park.
            const int64_t ref = (st == slot_state::abandoned) ? v.pinned_ts : v.connect_ts;
            if (addr->Timestamp - ref <= ttl_ticks_) {
                tracker_.note_syn(src_port, seq);
                act(st, pkt_buf, pkt_len, addr);
                return;
            }
            // The one legitimate way to be past the TTL on the same flow: a
            // retransmitted SYN (same ISN). Act on the state we already
            // hold; parking it would only add T and a watchdog count for a
            // packet that is already >= 1s late. A different ISN on the same
            // port is a new connection and takes the park path below.
            if (tracker_.is_retransmit(src_port, seq)) {
                parker_->note_retransmit();
                act(st, pkt_buf, pkt_len, addr);
                return;
            }
            parker_->note_ttl_stale();
        } else if (st == slot_state::pending) {
            // Item 19 path 5: the slot holds one pool index; a second SYN
            // must not allocate another. The parked one covers this flow.
            parker_->note_dup_syn();
            return;
        }

        tracker_.note_syn(src_port, seq);

        // Park (item 5: full copy of packet + address).
        if (pkt_len > syn_parker::MAX_PACKET) {
            parker_->note_oversize();
            passthrough(pkt_buf, pkt_len, addr);
            return;
        }
        const parked_ref ref = parker_->park(pkt_buf, pkt_len, *addr, src_port);
        if (ref.idx == NO_POOL_IDX) {
            // Item 8: controlled failure. Pass + pin, never evict.
            parker_->note_pool_exhausted();
            tracker_.pin_abandoned(src_port, v.word, addr->Timestamp);
            passthrough(pkt_buf, pkt_len, addr);
            return;
        }
        if (tracker_.try_park(src_port, v.word, ref.gen, ref.idx)) {
            parker_->note_parked();
            return;   // the injector sends it once the decision lands
        }
        // A decision landed between our load and our CAS: act on it now.
        parker_->note_cas_lost();
        parker_->free_slot(ref.idx);
        act(tracker_.load(src_port).state(), pkt_buf, pkt_len, addr);
    }

    void worker_loop(std::stop_token st) {
        // Stack-allocated buffers per worker, zero heap allocation
        uint8_t pkt_buf[65535];
        WINDIVERT_ADDRESS addr;

        while (!st.stop_requested() && running_) {
            UINT pkt_len = sizeof(pkt_buf);
            if (!WinDivertRecv(handle_, pkt_buf, pkt_len, &pkt_len, &addr)) {
                DWORD err = GetLastError();
                if (err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE) break;
                continue;
            }

            PWINDIVERT_IPHDR ip = nullptr;
            PWINDIVERT_TCPHDR tcp = nullptr;

            WinDivertHelperParsePacket(
                pkt_buf, pkt_len,
                &ip, nullptr, nullptr, nullptr, nullptr,
                &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);

            if (!ip || !tcp) {
                // Non-TCP/IP packet — passthrough unchanged
                WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, &addr);
                continue;
            }

            uint16_t src_port = ntohs(tcp->SrcPort);
            uint16_t dst_port = ntohs(tcp->DstPort);

            // Reply from the local listener -> app. The listener sends to
            // orig_dest_ip:app_port as the TCP peer; in Reflection mode that
            // is also outbound non-loopback, with src_port == redirect_port.
            if (src_port == redirect_port_) {
                reflect_reply(pkt_buf, pkt_len, ip, tcp, dst_port, &addr);
                nat_count_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            // Item 4: only the initial SYN can be parked. Outbound SYN+ACK
            // exists too (our acceptor and HTTP API listen), and every
            // later segment of a flow we never claimed passes through.
            const bool is_syn = tcp->Syn && !tcp->Ack;
            if (is_syn && parker_) {
                handle_syn(pkt_buf, pkt_len, ntohl(tcp->SeqNum), src_port, &addr);
                continue;
            }

            // Non-SYN (or parking off): the pre-parking hot path. After the
            // SYN is reflected, the app's later segments are still outbound to
            // the original destination (the kernel still thinks it is
            // connected there); their src_port is the app's port.
            if (tracker_.should_reflect(src_port)) {
                reflect_outbound_packet(handle_, pkt_buf, pkt_len, &addr, redirect_port_);
                nat_count_.fetch_add(1, std::memory_order_relaxed);
            } else {
                passthrough(pkt_buf, pkt_len, &addr);
            }
        }
    }

    // Reflection reply: listener → app (appears as outbound to orig dest)
    // Before: SrcAddr=AppIP, SrcPort=redirect_port, DstAddr=OrigDstIP, DstPort=AppPort
    // After:  SrcAddr=OrigDstIP, SrcPort=OrigDstPort, DstAddr=AppIP, DstPort=AppPort, Outbound=0
    void reflect_reply(uint8_t* pkt_buf, UINT pkt_len,
                       PWINDIVERT_IPHDR ip, PWINDIVERT_TCPHDR tcp,
                       uint16_t app_port, WINDIVERT_ADDRESS* addr)
    {
        // Lookup original destination from tracker (entry persists until connection close)
        if (!tracker_.should_reflect(app_port)) {
            // Unknown or already-closed connection — passthrough
            WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, addr);
            return;
        }

        const auto& entry = tracker_.peek(app_port);

        // Swap src/dst addresses
        uint32_t tmp = ip->SrcAddr;
        ip->SrcAddr = ip->DstAddr;
        ip->DstAddr = tmp;

        // Restore SrcPort to original destination port
        // (app expects replies from OrigDstIP:OrigDstPort)
        tcp->SrcPort = htons(entry.remote_port);

        // Reinject as inbound
        addr->Outbound = 0;

        WinDivertHelperCalcChecksums(pkt_buf, pkt_len, addr, 0);

        if (!WinDivertSend(handle_, pkt_buf, pkt_len, nullptr, addr)) {
            PC_LOG_ERROR("[WD-NETWORK] Send (reflect reply) failed: {}", GetLastError());
        }
    }
};

} // namespace clew
