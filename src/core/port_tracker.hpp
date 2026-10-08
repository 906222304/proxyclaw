#pragma once

// PortTracker: 65536 fixed-size array for O(1) lock-free port -> decision mapping.
//
// Each local TCP port has one slot holding a four-state word:
//   empty      no flow on this port that we know about
//   pending    the NETWORK worker parked this flow's SYN in the pool and is
//              waiting for the SOCKET side to publish a decision
//   proxied    reflect this flow to the local acceptor (group_id says where)
//   direct     decided: leave the flow alone
//   abandoned  no decision arrived in time; the watchdog released the SYN
//              and pinned the port so a late decision cannot hijack the flow
//
// `direct` and `abandoned` behave the same on the wire. They are kept apart
// because one is a decision and the other is the absence of one, and the
// counters that tell "proxy missed a flow" from "harmless direct traffic"
// depend on that distinction.
//
// The word packs {state:8 | pool generation:24 | pool index:32} into one
// 64-bit atomic so every transition is a single CAS and the CAS winner owns
// the pool index. Decided states always carry generation 0 / NO_POOL_IDX.
//
// Who writes what (see docs/ARCHITECTURE.md, "SYN parking"):
//   strand (SOCKET handler, relay teardown posted to it)
//       every publish, every clear
//   NETWORK workers
//       empty -> pending only (try_park), plus pin_abandoned when the pool is
//       full
//   injector thread (watchdog sweep)
//       pending -> abandoned only
// The only cross-thread races are the transitions out of `pending`, and the
// word CAS settles all of them.
//
// Auxiliary fields (timestamps, remote endpoint) are written before the
// release-CAS and read after an acquire load. A writer that then loses its
// CAS has clobbered aux fields on a slot whose new state does not read them:
// `abandoned` reads only pinned_ts, decided states read only connect_ts /
// entry, so the clobber is harmless. Keep that property when adding fields.
//
// All timestamps are WINDIVERT_ADDRESS.Timestamp values: kernel QPC ticks,
// the same clock at the SOCKET and NETWORK layers.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <optional>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace clew {

enum class slot_state : uint8_t {
    empty     = 0,
    pending   = 1,
    proxied   = 2,
    direct    = 3,
    abandoned = 4,
};

inline const char* slot_state_name(slot_state s) {
    switch (s) {
    case slot_state::empty:     return "empty";
    case slot_state::pending:   return "pending";
    case slot_state::proxied:   return "proxied";
    case slot_state::direct:    return "direct";
    case slot_state::abandoned: return "abandoned";
    }
    return "?";
}

constexpr uint32_t NO_POOL_IDX = 0xFFFFFFFFu;

constexpr uint64_t pack_word(slot_state st, uint32_t gen, uint32_t idx) {
    return (static_cast<uint64_t>(st) << 56)
         | (static_cast<uint64_t>(gen & 0xFFFFFFu) << 32)
         | static_cast<uint64_t>(idx);
}
constexpr slot_state word_state(uint64_t w) { return static_cast<slot_state>(w >> 56); }
constexpr uint32_t   word_gen(uint64_t w)   { return static_cast<uint32_t>((w >> 32) & 0xFFFFFFu); }
constexpr uint32_t   word_idx(uint64_t w)   { return static_cast<uint32_t>(w & 0xFFFFFFFFu); }
constexpr uint64_t   decided_word(slot_state st) { return pack_word(st, 0, NO_POOL_IDX); }
constexpr uint64_t   EMPTY_WORD = decided_word(slot_state::empty);

struct TrackerEntry {
    uint32_t remote_addr[4]{};  // host byte order (WinDivert SOCKET layer native); IPv4 in [0]
    uint16_t remote_port{0};    // host byte order
    uint32_t group_id{0};
};

// Slots are published lock-free: the writer fills the entry and then flips
// the word with release semantics, and nothing stops the writer from
// overwriting a slot a reader is still copying. That is only survivable while a
// torn read costs at most one misrouted packet, which requires the entry to be
// plain bytes. A member with a non-trivial copy (shared_ptr, string, vector)
// turns the same race into heap corruption — keep heap-owned data out of here.
static_assert(std::is_trivially_copyable_v<TrackerEntry>,
              "TrackerEntry must stay trivially copyable — see the comment above");

struct alignas(64) TrackerSlot {
    std::atomic<uint64_t> word{EMPTY_WORD};
    int64_t      connect_ts{0};   // kernel Timestamp of the CONNECT that produced the decision (strand-owned)
    int64_t      pinned_ts{0};    // kernel Timestamp of the SYN the watchdog released (injector/worker-owned)
    TrackerEntry entry{};
    std::atomic<uint32_t> syn_seq{0};   // ISN of the last SYN the NETWORK worker handled on this port (worker-owned)
};

// alignas(64) is the false-sharing defense for the lock-free worker reads;
// the table is 65536 x 64B = 4 MiB and lives on the heap.
static_assert(sizeof(TrackerSlot) == 64, "TrackerSlot must stay one cache line");

// What a NETWORK worker sees when it looks at a port.
struct slot_view {
    uint64_t word;
    int64_t  connect_ts;
    int64_t  pinned_ts;
    slot_state state() const { return word_state(word); }
};

// Pool entry handed from the worker (park) to the strand (publish) to the
// injector (release). The generation is re-checked at release.
struct parked_ref {
    uint32_t idx;
    uint32_t gen;
};

enum class publish_outcome : uint8_t {
    stored,           // slot was empty (or held a stale decision): decision written, no packet parked
    released_parked,  // slot was pending: decision written, caller must release parked_ref
    late_rejected,    // slot was abandoned by the watchdog for this very flow: decision dropped
};

struct publish_result {
    publish_outcome outcome;
    parked_ref      parked{NO_POOL_IDX, 0};   // valid only for released_parked
};

class PortTracker {
public:
    PortTracker() {
        LARGE_INTEGER f{};
        QueryPerformanceFrequency(&f);
        qpc_freq_  = f.QuadPart > 0 ? f.QuadPart : 10'000'000;
        ttl_ticks_ = ms_to_ticks(10);
    }

    // Kernel-timestamp TTL for "a decision on this slot still belongs to the
    // SYN that just arrived". Same-flow delta is microseconds; stale leftovers
    // are seconds old. 10ms sits orders of magnitude from both.
    int64_t ttl_ticks() const { return ttl_ticks_; }
    int64_t ms_to_ticks(int64_t ms) const { return ms * qpc_freq_ / 1000; }
    int64_t qpc_frequency() const { return qpc_freq_; }

    // ---- NETWORK workers ----------------------------------------------

    // Non-SYN outbound packet on this port: reflect it?
    bool should_reflect(uint16_t port) const {
        return word_state(slots_[port].word.load(std::memory_order_acquire)) == slot_state::proxied;
    }

    // Entry for the reflect_reply path. Only meaningful after should_reflect.
    const TrackerEntry& peek(uint16_t port) const {
        return slots_[port].entry;
    }

    slot_view load(uint16_t port) const {
        const auto& s = slots_[port];
        slot_view v;
        v.word       = s.word.load(std::memory_order_acquire);
        v.connect_ts = s.connect_ts;
        v.pinned_ts  = s.pinned_ts;
        return v;
    }

    // Remember the ISN of the SYN being handled on this port. Written by the
    // worker on every SYN it acts on or parks (not on duplicates it drops).
    void note_syn(uint16_t port, uint32_t seq) {
        slots_[port].syn_seq.store(seq, std::memory_order_relaxed);
    }

    // A SYN that repeats the ISN of the last one on this port is the same
    // connection retransmitting (RTO >= 1s, so it is always past the TTL).
    // Windows randomises the ISN per connection, so a genuinely new flow on
    // the reused port carries a different one and takes the TTL path.
    bool is_retransmit(uint16_t port, uint32_t seq) const {
        return slots_[port].syn_seq.load(std::memory_order_relaxed) == seq;
    }

    // The worker's only transition: `expected` -> pending(gen, idx). Fails when
    // a decision landed in between; the caller then re-reads and acts on it.
    bool try_park(uint16_t port, uint64_t expected, uint32_t gen, uint32_t idx) {
        return slots_[port].word.compare_exchange_strong(
            expected, pack_word(slot_state::pending, gen, idx),
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    // Watchdog (injector sweep) and pool-exhaustion path: `expected` ->
    // abandoned, pinned at the SYN's kernel timestamp so a later publish for
    // the same flow is recognised as late.
    bool pin_abandoned(uint16_t port, uint64_t expected, int64_t syn_ts) {
        auto& s = slots_[port];
        s.pinned_ts = syn_ts;   // aux before the release-CAS
        return s.word.compare_exchange_strong(
            expected, decided_word(slot_state::abandoned),
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    // ---- strand ---------------------------------------------------------

    // Our own re-injected SYN re-traverses ALE and produces a second CONNECT
    // for the same flow (from PID 4). A slot that already holds a decision
    // younger than the TTL for the same remote endpoint is that echo.
    bool is_echo(uint16_t port, int64_t connect_ts,
                 const uint32_t (&remote_addr)[4], uint16_t remote_port) const {
        const auto& s = slots_[port];
        const auto st = word_state(s.word.load(std::memory_order_acquire));
        if (st != slot_state::proxied && st != slot_state::direct) return false;
        if (connect_ts - s.connect_ts > ttl_ticks_) return false;
        return s.entry.remote_port == remote_port
            && std::memcmp(s.entry.remote_addr, remote_addr, sizeof(s.entry.remote_addr)) == 0;
    }

    // Exactly one call per CONNECT. `decision` is proxied or direct.
    publish_result publish(uint16_t port, slot_state decision,
                           const TrackerEntry& e, int64_t connect_ts) {
        auto& s = slots_[port];
        for (;;) {
            uint64_t   w  = s.word.load(std::memory_order_acquire);
            const auto st = word_state(w);

            if (st == slot_state::abandoned && connect_ts < s.pinned_ts) {
                // The watchdog already released this flow. Item 7: reject.
                return {publish_outcome::late_rejected};
            }

            // Aux first, then the release-CAS.
            s.connect_ts = connect_ts;
            s.entry      = e;

            if (st == slot_state::pending) {
                const parked_ref ref{word_idx(w), word_gen(w)};
                if (s.word.compare_exchange_strong(w, decided_word(decision),
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire)) {
                    return {publish_outcome::released_parked, ref};
                }
                continue;   // watchdog won: loop re-reads abandoned and rejects
            }

            if (s.word.compare_exchange_strong(w, decided_word(decision),
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
                return {publish_outcome::stored};
            }
            // A worker parked a SYN between our load and our CAS: loop.
        }
    }

    // SOCKET CLOSE for this port. Returns the pool index to return when the
    // flow was still pending (its parked SYN is dropped: the socket is gone).
    // `proxied` slots are left alone — CLOSE fires at closesocket(), before
    // the wire is done; the relay clears them at teardown via clear_if.
    std::optional<uint32_t> on_close(uint16_t port, int64_t close_ts) {
        auto& s = slots_[port];
        for (;;) {
            uint64_t   w  = s.word.load(std::memory_order_acquire);
            const auto st = word_state(w);
            if (st == slot_state::empty) return std::nullopt;
            if (s.connect_ts > close_ts) return std::nullopt;   // CLOSE of a previous flow on this port
            if (st == slot_state::proxied) return std::nullopt;
            if (st == slot_state::pending) {
                const uint32_t idx = word_idx(w);
                if (s.word.compare_exchange_strong(w, EMPTY_WORD,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire)) {
                    return idx;
                }
                continue;
            }
            if (s.word.compare_exchange_strong(w, EMPTY_WORD,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
                return std::nullopt;
            }
        }
    }

    // Relay teardown (posted to the strand): clear only if the slot still
    // belongs to the flow the relay served. The app may have closed, reused
    // the port and published a new decision in the meantime.
    bool clear_if(uint16_t port, int64_t connect_ts) {
        auto& s = slots_[port];
        for (;;) {
            uint64_t w = s.word.load(std::memory_order_acquire);
            if (word_state(w) == slot_state::empty) return false;
            if (s.connect_ts != connect_ts) return false;
            if (s.word.compare_exchange_strong(w, EMPTY_WORD,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
                return true;
            }
        }
    }

    // ---- relay --------------------------------------------------------

    struct taken {
        TrackerEntry entry;
        int64_t      connect_ts;
    };

    // Called from the relay coroutine on accept. Non-destructive; the entry
    // stays `proxied` for the NETWORK layer until the relay tears down.
    std::optional<taken> take(uint16_t port) const {
        const auto& s = slots_[port];
        if (word_state(s.word.load(std::memory_order_acquire)) != slot_state::proxied) {
            return std::nullopt;
        }
        return taken{s.entry, s.connect_ts};
    }

    // ---- diagnostics / tests --------------------------------------------

    slot_state state(uint16_t port) const {
        return word_state(slots_[port].word.load(std::memory_order_acquire));
    }

private:
    std::array<TrackerSlot, 65536> slots_{};
    int64_t qpc_freq_{10'000'000};
    int64_t ttl_ticks_{100'000};
};

} // namespace clew
