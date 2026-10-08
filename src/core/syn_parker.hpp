#pragma once

// syn_parker: the SYN-parking pool and injector thread.
//
// The NETWORK worker sees an outbound SYN whose port has no decision yet.
// Instead of releasing it (and losing the flow to the direct path, which is
// what made fresh git/curl/gh processes escape 100% of the time), it copies
// the packet plus its WINDIVERT_ADDRESS into a bounded pool and marks the
// port `pending` in the PortTracker. When the SOCKET side publishes the
// decision, the strand hands the pool index to this class; the injector
// thread copies the packet out, frees the slot, and sends it — verbatim for
// `direct`, reflected to the acceptor for `proxied`.
//
// The watchdog is a periodic sweep on the same injector thread: any packet
// parked longer than T is released unchanged and its port pinned
// `abandoned`, so a decision that arrives later cannot hijack a flow that is
// already established. Two counters tell the two failure modes apart:
// released_by_watchdog (may be harmless direct traffic) and
// late_decision_rejected (a proxied decision that came too late: proxy
// missed). Neither should be non-zero in normal operation.
//
// Why a thread of its own: WinDivertSend is a 47-190us syscall; the strand
// only publishes. Why copy-out-then-free: a 1500B memcpy is ~0.15us against
// the send, so holding the slot across the send would halve pool turnover
// for nothing.
//
// Timer: a plain 1ms wait is quantised to the 15.625ms system tick. The
// sweep uses a high-resolution waitable timer (Win10 1803+, measured p50
// 1.04ms) and falls back to the ordinary timer if that is unavailable.
//
// Design record: memory project/syn_parking/design.md; measurements in the
// PoC report (win_prox/tools/poc/poc_syn_parking_report.md).

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <windivert.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#include "core/log.hpp"
#include "core/port_tracker.hpp"

namespace clew {

// Reflection forward transform, shared by the NETWORK worker (live buffer)
// and the injector (pool copy): app -> original_dest becomes inbound to the
// local acceptor. Swaps addresses, rewrites DstPort, flips Outbound,
// recalculates checksums, sends. Returns false if the packet could not be
// parsed (then it is sent unchanged) or the send failed.
inline bool reflect_outbound_packet(HANDLE handle, uint8_t* pkt, UINT len,
                                    WINDIVERT_ADDRESS* addr, uint16_t redirect_port) {
    PWINDIVERT_IPHDR  ip  = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    WinDivertHelperParsePacket(pkt, len, &ip, nullptr, nullptr, nullptr, nullptr,
                               &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!ip || !tcp) {
        WinDivertSend(handle, pkt, len, nullptr, addr);
        return false;
    }
    const uint32_t tmp = ip->SrcAddr;
    ip->SrcAddr = ip->DstAddr;
    ip->DstAddr = tmp;
    tcp->DstPort = htons(redirect_port);
    addr->Outbound = 0;
    WinDivertHelperCalcChecksums(pkt, len, addr, 0);
    if (!WinDivertSend(handle, pkt, len, nullptr, addr)) {
        PC_LOG_ERROR("[WD-NETWORK] Send (reflect out) failed: {}", GetLastError());
        return false;
    }
    return true;
}

// Plain snapshot for /api/stats and the periodic log line. No atomics, no
// WinDivert types, so it can cross into the services layer.
struct syn_parking_counters {
    uint64_t parked               = 0;  // SYNs copied into the pool
    uint64_t released_by_decision = 0;
    uint64_t released_by_watchdog = 0;  // item 7, counter 1
    uint64_t released_by_drain    = 0;  // shutdown
    uint64_t ttl_stale            = 0;  // SYN found a decision older than the TTL -> parked anyway
    uint64_t retransmit_passed    = 0;  // past the TTL but same ISN: acted on the held state, not parked
    uint64_t dup_syn_dropped      = 0;  // second SYN while pending (item 19 path 5)
    uint64_t cas_lost_to_decision = 0;  // decision landed between the worker's load and its CAS
    uint64_t pool_exhausted       = 0;  // item 8: passed + pinned abandoned instead of parked
    uint64_t oversize             = 0;  // SYN larger than a pool entry (expect 0)
    uint64_t gen_mismatch         = 0;  // pool generation check failed at release (must be 0)
    uint64_t send_failures        = 0;
    uint64_t pool_in_use          = 0;  // leak signal: must return to 0 between bursts
    uint64_t pool_peak            = 0;
    uint64_t park_us_max          = 0;
    uint64_t park_us_sum          = 0;  // over released_by_decision, for the mean
    uint32_t pool_size            = 0;
    uint32_t watchdog_ms          = 0;
    bool     hires_timer          = false;
};

class syn_parker {
public:
    static constexpr size_t   MAX_PACKET = 2048;   // any SYN fits (TFO data <= MSS, never LSO-coalesced)
    static constexpr uint32_t MIN_POOL   = 32;
    static constexpr uint32_t MAX_POOL   = 4096;
    static constexpr int      MIN_WATCHDOG_MS = 5;
    static constexpr int      MAX_WATCHDOG_MS = 50;

    syn_parker(PortTracker& tracker, int watchdog_ms, uint32_t pool_size)
        : tracker_(tracker)
    {
        watchdog_ms_ = watchdog_ms < MIN_WATCHDOG_MS ? MIN_WATCHDOG_MS
                     : watchdog_ms > MAX_WATCHDOG_MS ? MAX_WATCHDOG_MS : watchdog_ms;
        pool_size_   = pool_size < MIN_POOL ? MIN_POOL
                     : pool_size > MAX_POOL ? MAX_POOL : pool_size;
        watchdog_ticks_ = tracker_.ms_to_ticks(watchdog_ms_);
        pool_ = std::vector<pool_entry>(pool_size_);
        queue_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }

    ~syn_parker() {
        stop();
        if (queue_event_) CloseHandle(queue_event_);
    }

    syn_parker(const syn_parker&)            = delete;
    syn_parker& operator=(const syn_parker&) = delete;

    int      watchdog_ms() const { return watchdog_ms_; }
    uint32_t pool_size()   const { return pool_size_; }

    // ---- lifecycle (app) ------------------------------------------------

    // `handle` is the NETWORK-layer WinDivert handle (must stay open until
    // stop() returns: the shutdown drain sends through it).
    void start(HANDLE handle, uint16_t redirect_port) {
        handle_        = handle;
        redirect_port_ = redirect_port;
        running_       = true;
        injector_ = std::jthread([this]() { injector_loop(); });
        PC_LOG_INFO("[SYN-PARK] injector started: watchdog={}ms pool={} ttl={}ms",
                    watchdog_ms_, pool_size_, 10);
    }

    // Releases everything still parked (as abandoned, unchanged) and joins.
    void stop() {
        if (!running_.exchange(false)) return;
        if (queue_event_) SetEvent(queue_event_);
        if (injector_.joinable()) injector_.join();
        const auto c = snapshot();
        PC_LOG_INFO("[SYN-PARK] injector stopped: parked={} decision={} watchdog={} drain={} "
                    "ttl_stale={} dup={} cas_lost={} exhausted={} gen_mismatch={} "
                    "peak={} park_us_max={}",
                    c.parked, c.released_by_decision, c.released_by_watchdog,
                    c.released_by_drain, c.ttl_stale, c.dup_syn_dropped,
                    c.cas_lost_to_decision, c.pool_exhausted, c.gen_mismatch,
                    c.pool_peak, c.park_us_max);
    }

    // ---- NETWORK worker ---------------------------------------------------

    // Copy a SYN into the pool. Returns the (idx, gen) to CAS into the slot,
    // or NO_POOL_IDX if the pool is full (caller pins the port abandoned and
    // passes the packet through).
    parked_ref park(const uint8_t* pkt, UINT len, const WINDIVERT_ADDRESS& addr, uint16_t port) {
        const uint32_t idx = alloc();
        if (idx == NO_POOL_IDX) return {NO_POOL_IDX, 0};
        pool_entry& e = pool_[idx];
        std::memcpy(e.pkt, pkt, len);
        e.len           = len;
        e.addr          = addr;
        e.port          = port;
        e.syn_kernel_ts = addr.Timestamp;
        e.park_qpc      = now_qpc();
        return {idx, e.gen.load(std::memory_order_acquire)};
    }

    // Return a slot without sending (park CAS lost, or CLOSE while pending).
    void free_slot(uint32_t idx) { free(idx); }

    // Counters the worker bumps directly.
    void note_parked()          { bump(parked_); }
    void note_ttl_stale()       { bump(ttl_stale_); }
    void note_retransmit()      { bump(retransmit_passed_); }
    void note_dup_syn()         { bump(dup_syn_dropped_); }
    void note_cas_lost()        { bump(cas_lost_to_decision_); }
    void note_oversize()        { bump(oversize_); }
    void note_pool_exhausted() {
        const auto n = pool_exhausted_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n == 1 || n % 1000 == 0) {
            PC_LOG_WARN("[SYN-PARK] pool exhausted ({} times): SYNs pass through direct "
                        "and are pinned; if this persists the pool is leaking or too small",
                        n);
        }
    }

    // ---- strand ------------------------------------------------------------

    // The decision for a parked flow landed: hand the slot to the injector.
    void release(parked_ref ref, uint16_t port, slot_state decision) {
        {
            std::lock_guard<std::mutex> lk(queue_mu_);
            queue_.push_back({ref.idx, ref.gen, port, decision});
        }
        SetEvent(queue_event_);
    }

    // ---- stats -------------------------------------------------------------

    syn_parking_counters snapshot() const {
        syn_parking_counters c;
        c.parked               = parked_.load();
        c.released_by_decision = released_by_decision_.load();
        c.released_by_watchdog = released_by_watchdog_.load();
        c.released_by_drain    = released_by_drain_.load();
        c.ttl_stale            = ttl_stale_.load();
        c.retransmit_passed    = retransmit_passed_.load();
        c.dup_syn_dropped      = dup_syn_dropped_.load();
        c.cas_lost_to_decision = cas_lost_to_decision_.load();
        c.pool_exhausted       = pool_exhausted_.load();
        c.oversize             = oversize_.load();
        c.gen_mismatch         = gen_mismatch_.load();
        c.send_failures        = send_failures_.load();
        c.pool_in_use          = static_cast<uint64_t>(pool_in_use_.load());
        c.pool_peak            = static_cast<uint64_t>(pool_peak_.load());
        c.park_us_max          = park_us_max_.load();
        c.park_us_sum          = park_us_sum_.load();
        c.pool_size            = pool_size_;
        c.watchdog_ms          = static_cast<uint32_t>(watchdog_ms_);
        c.hires_timer          = hires_timer_.load();
        return c;
    }

private:
    struct pool_entry {
        std::atomic<bool>     in_use{false};
        std::atomic<uint32_t> gen{1};        // bumped on every free; 0 is never live
        int64_t               park_qpc = 0;
        int64_t               syn_kernel_ts = 0;
        uint16_t              port = 0;
        UINT                  len = 0;
        WINDIVERT_ADDRESS     addr{};
        uint8_t               pkt[MAX_PACKET];
    };

    struct release_req {
        uint32_t   idx;
        uint32_t   gen;
        uint16_t   port;
        slot_state decision;
    };

    PortTracker& tracker_;
    HANDLE       handle_{INVALID_HANDLE_VALUE};
    uint16_t     redirect_port_{0};
    int          watchdog_ms_{20};
    uint32_t     pool_size_{256};
    int64_t      watchdog_ticks_{0};

    std::vector<pool_entry> pool_;
    std::atomic<uint32_t>   pool_hint_{0};
    std::atomic<int32_t>    pool_in_use_{0};
    std::atomic<int32_t>    pool_peak_{0};

    std::mutex              queue_mu_;
    std::deque<release_req> queue_;
    HANDLE                  queue_event_{nullptr};

    std::atomic<bool> running_{false};
    std::atomic<bool> hires_timer_{false};
    std::jthread      injector_;

    std::atomic<uint64_t> parked_{0}, released_by_decision_{0}, released_by_watchdog_{0},
                          released_by_drain_{0}, ttl_stale_{0}, retransmit_passed_{0}, dup_syn_dropped_{0},
                          cas_lost_to_decision_{0}, pool_exhausted_{0}, oversize_{0},
                          gen_mismatch_{0}, send_failures_{0}, park_us_max_{0}, park_us_sum_{0};

    static void bump(std::atomic<uint64_t>& c) { c.fetch_add(1, std::memory_order_relaxed); }

    static int64_t now_qpc() {
        LARGE_INTEGER t;
        QueryPerformanceCounter(&t);
        return t.QuadPart;
    }

    uint64_t ticks_to_us(int64_t ticks) const {
        return static_cast<uint64_t>(ticks * 1'000'000 / tracker_.qpc_frequency());
    }

    // ---- pool --------------------------------------------------------------

    uint32_t alloc() {
        const uint32_t n = pool_size_;
        const uint32_t start = pool_hint_.fetch_add(1, std::memory_order_relaxed) % n;
        for (uint32_t k = 0; k < n; ++k) {
            const uint32_t i = (start + k) % n;
            bool expected = false;
            if (pool_[i].in_use.compare_exchange_strong(expected, true,
                                                        std::memory_order_acq_rel,
                                                        std::memory_order_relaxed)) {
                const int32_t used = pool_in_use_.fetch_add(1, std::memory_order_relaxed) + 1;
                int32_t peak = pool_peak_.load(std::memory_order_relaxed);
                while (used > peak &&
                       !pool_peak_.compare_exchange_weak(peak, used, std::memory_order_relaxed)) {}
                return i;
            }
        }
        return NO_POOL_IDX;
    }

    void free(uint32_t idx) {
        pool_entry& e = pool_[idx];
        e.gen.fetch_add(1, std::memory_order_acq_rel);   // bump before releasing: the next owner sees a new gen
        e.in_use.store(false, std::memory_order_release);
        pool_in_use_.fetch_sub(1, std::memory_order_relaxed);
    }

    // ---- injector thread -----------------------------------------------------

    void injector_loop() {
        HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr,
                                              CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                              TIMER_ALL_ACCESS);
        if (timer) {
            hires_timer_ = true;
        } else {
            PC_LOG_WARN("[SYN-PARK] high-resolution timer unavailable ({}); watchdog "
                        "granularity falls back to the system tick (~15.6ms)",
                        GetLastError());
            timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS);
        }
        if (timer) {
            LARGE_INTEGER due;
            due.QuadPart = -10000;   // 1ms, relative
            SetWaitableTimer(timer, &due, 1, nullptr, nullptr, FALSE);
        }

        HANDLE waits[2] = {queue_event_, timer};
        const DWORD nwaits = timer ? 2 : 1;

        int64_t last_summary = now_qpc();
        uint64_t last_summary_key = 0;
        const int64_t summary_ticks = tracker_.ms_to_ticks(60'000);

        while (running_.load(std::memory_order_relaxed)) {
            WaitForMultipleObjects(nwaits, waits, FALSE, 50);
            drain_queue();
            sweep(/*force=*/false);

            const int64_t now = now_qpc();
            if (now - last_summary >= summary_ticks) {
                last_summary = now;
                const auto c = snapshot();
                const uint64_t key = c.parked + c.released_by_watchdog * 1000003ull
                                   + c.pool_exhausted * 1000033ull + c.gen_mismatch;
                if (key != last_summary_key) {
                    last_summary_key = key;
                    PC_LOG_INFO("[SYN-PARK] parked={} decision={} watchdog={} ttl_stale={} "
                                "exhausted={} in_use={} peak={} park_us_max={} park_us_mean={}",
                                c.parked, c.released_by_decision, c.released_by_watchdog,
                                c.ttl_stale, c.pool_exhausted, c.pool_in_use, c.pool_peak,
                                c.park_us_max,
                                c.released_by_decision ? c.park_us_sum / c.released_by_decision : 0);
                }
            }
        }

        // Release path 4: shutdown drain. Nothing may stay parked.
        drain_queue();
        sweep(/*force=*/true);
        if (timer) CloseHandle(timer);
    }

    void drain_queue() {
        for (;;) {
            release_req r;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                if (queue_.empty()) return;
                r = queue_.front();
                queue_.pop_front();
            }
            release_parked(r.idx, r.gen, r.decision, released_by_decision_);
        }
    }

    // Watchdog: every pool entry older than T whose slot still says
    // pending(idx == this entry) is pinned abandoned and sent unchanged.
    void sweep(bool force) {
        const int64_t now = now_qpc();
        for (uint32_t i = 0; i < pool_size_; ++i) {
            pool_entry& e = pool_[i];
            if (!e.in_use.load(std::memory_order_acquire)) continue;
            if (!force && now - e.park_qpc < watchdog_ticks_) continue;

            const auto v = tracker_.load(e.port);
            if (v.state() != slot_state::pending || word_idx(v.word) != i) continue;   // not (or no longer) ours
            const uint32_t gen = word_gen(v.word);
            if (!tracker_.pin_abandoned(e.port, v.word, e.syn_kernel_ts)) continue;   // decision won the race

            if (!force) {
                PC_LOG_DEBUG("[SYN-PARK] watchdog released port={} after {}us",
                             e.port, ticks_to_us(now - e.park_qpc));
            }
            release_parked(i, gen, slot_state::abandoned,
                           force ? released_by_drain_ : released_by_watchdog_);
        }
    }

    // Copy out, free the slot, then send (item 20).
    void release_parked(uint32_t idx, uint32_t gen, slot_state decision,
                        std::atomic<uint64_t>& counter) {
        pool_entry& e = pool_[idx];
        if (e.gen.load(std::memory_order_acquire) != gen) {
            bump(gen_mismatch_);   // must never happen: the CAS owner is the only one holding this ref
            PC_LOG_ERROR("[SYN-PARK] pool generation mismatch idx={} (expected {}, have {})",
                         idx, gen, e.gen.load());
            return;
        }

        uint8_t           pkt[MAX_PACKET];
        WINDIVERT_ADDRESS addr = e.addr;
        const UINT        len  = e.len;
        const int64_t     park = e.park_qpc;
        std::memcpy(pkt, e.pkt, len);
        free(idx);

        const uint64_t park_us = ticks_to_us(now_qpc() - park);
        bump(counter);
        if (&counter == &released_by_decision_) {
            park_us_sum_.fetch_add(park_us, std::memory_order_relaxed);
            uint64_t mx = park_us_max_.load(std::memory_order_relaxed);
            while (park_us > mx &&
                   !park_us_max_.compare_exchange_weak(mx, park_us, std::memory_order_relaxed)) {}
        }

        bool ok;
        if (decision == slot_state::proxied) {
            ok = reflect_outbound_packet(handle_, pkt, len, &addr, redirect_port_);
        } else {
            ok = WinDivertSend(handle_, pkt, len, nullptr, &addr) != FALSE;
            if (!ok) PC_LOG_ERROR("[SYN-PARK] release send failed: {}", GetLastError());
        }
        if (!ok) bump(send_failures_);
    }
};

} // namespace clew
