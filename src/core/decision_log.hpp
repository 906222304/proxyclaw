#pragma once

// DecisionLog: what the data path decided for each connection, recorded at
// decision time (ROADMAP v0.14 #2).
//
// The connection list used to recompute "proxied" against the *current*
// rules on every poll, so editing a rule rewrote the history of connections
// that were already established. The data path now writes one record per
// decision here, and the list reads the record instead.
//
// Layout
//   ring_     fixed-size ring of POD records (capacity: power of two, set at
//             construction, never reallocated). The newest `capacity` records
//             survive; older ones are evicted by overwrite.
//   index     one ticket per local port per transport (TCP, UDP), 2 x 65536
//             atomics: the newest record for that port. Each record carries
//             the ticket of the previous record for the same port, so a
//             lookup can walk back a short chain (port reuse towards a
//             different remote) until it hits an evicted ticket.
//
// Writers: the strand (TCP / UDP SOCKET decisions), the SYN-parker injector
// (watchdog release), a NETWORK worker (pool exhausted), the UDP park
// watchdog. Readers: the connection list (any thread). So the ring is
// multi-producer / multi-consumer and lock-free:
//   - a writer takes a ticket (fetch_add), claims slot ticket & mask with a
//     CAS on its sequence word (odd = being written), stores the payload as
//     relaxed atomic words and publishes the sequence 2*ticket+2 (release);
//   - a reader loads the sequence, copies the words, re-loads the sequence
//     (seqlock) and accepts the copy only when both equal 2*ticket+2.
// A writer that finds its slot still being written by an older ticket, or
// already taken by a newer one (the ring lapped it), drops its record and
// counts it (`dropped`); the lookup then falls back to recomputing.
//
// Hot path cost: one fetch_add, one CAS, nine relaxed stores, one release
// store and one CAS on the port index. No allocation, no lock, no syscall.
// Everything here is std-only so it is unit tested on any platform.

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <type_traits>

namespace clew {

enum class decision_proto : uint8_t { tcp = 0, udp = 1 };

enum class decision_verdict : uint8_t { direct = 0, proxied = 1 };

// Why the verdict is what it is. The route reasons keep the names of
// ip_exclude_reason_name() (rules/traffic_filter.hpp) so the connection
// list's `route_reason` keeps its vocabulary.
enum class decision_reason : uint8_t {
    none = 0,                 // proxied
    self,                     // ProxyClaw's own connection
    unknown_pid,              // PID not in the tree and not resolvable
    not_proxied,              // process matched no rule / hijack
    global_exclude,
    rule_exclude,
    rule_exclude_port,
    rule_include_cidr_miss,
    rule_include_port_miss,
    rule_protocol,
    late,                     // decision arrived after the watchdog released the SYN
    watchdog,                 // no decision in time: released direct by the watchdog
    pool_exhausted,           // SYN parking pool full: passed direct
    ipv6,                     // IPv6 remote: not managed, goes direct
};

inline const char* decision_reason_name(decision_reason r) noexcept {
    switch (r) {
    case decision_reason::none:                   return "none";
    case decision_reason::self:                   return "self";
    case decision_reason::unknown_pid:            return "unknown-pid";
    case decision_reason::not_proxied:            return "not-proxied";
    case decision_reason::global_exclude:         return "global_exclude";
    case decision_reason::rule_exclude:           return "rule_exclude";
    case decision_reason::rule_exclude_port:      return "rule_exclude_port";
    case decision_reason::rule_include_cidr_miss: return "rule_include_cidr_miss";
    case decision_reason::rule_include_port_miss: return "rule_include_port_miss";
    case decision_reason::rule_protocol:          return "rule_protocol";
    case decision_reason::late:                   return "late";
    case decision_reason::watchdog:               return "watchdog";
    case decision_reason::pool_exhausted:         return "pool_exhausted";
    case decision_reason::ipv6:                   return "ipv6";
    }
    return "none";
}

// Where the process's proxy state came from at decision time.
enum class decision_source : uint8_t {
    none = 0,   // not proxied / not known
    rule,       // matched an auto rule by name (+ cmdline / path filters)
    tree,       // inherited from a rule-matched ancestor (process tree)
    manual,     // manual hijack (directly or inherited from a hijacked parent)
};

inline const char* decision_source_name(decision_source s) noexcept {
    switch (s) {
    case decision_source::rule:   return "rule";
    case decision_source::tree:   return "tree";
    case decision_source::manual: return "manual";
    default:                      return "none";
    }
}

namespace decision_flags {
    inline constexpr uint8_t IPV6          = 0x01;  // remote_addr is a real IPv6 address
    inline constexpr uint8_t LATE_PROXIED  = 0x02;  // reason late: the rejected decision was `proxied`
}

inline constexpr uint32_t DECISION_NO_GROUP = 0xFFFFFFFFu;

// One decision. Plain bytes, exactly 64: it is copied word by word through
// the seqlock. Keep it trivially copyable and a multiple of 8 bytes.
struct DecisionRecord {
    uint64_t psn{0};                 // process sequence number (0 = unknown)
    int64_t  at_ms{0};               // wall clock, ms since the Unix epoch
    uint64_t config_version{0};      // rule_engine_v3::config_version() at decision time
    uint32_t remote_addr[4]{};       // host byte order; IPv4 in [0], rest 0
    uint32_t pid{0};                 // 0 = not known at this layer (watchdog, pool)
    uint32_t group_id{DECISION_NO_GROUP};
    uint32_t policy_id{0};           // rule's runtime policy id (0 = no rule)
    uint16_t local_port{0};
    uint16_t remote_port{0};         // host byte order; 0 = none (UDP BIND)
    decision_proto   proto{decision_proto::tcp};
    decision_verdict verdict{decision_verdict::direct};
    decision_reason  reason{decision_reason::none};
    decision_source  source{decision_source::none};
    uint8_t  flags{0};
    uint8_t  pad_[3]{};
};

static_assert(std::is_trivially_copyable_v<DecisionRecord>,
              "DecisionRecord is copied through a seqlock as raw words");
static_assert(sizeof(DecisionRecord) == 64, "DecisionRecord must stay 64 bytes");

inline int64_t decision_now_ms() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

class DecisionLog {
public:
    static constexpr std::size_t DEFAULT_CAPACITY = 16384;
    static constexpr int         MAX_CHAIN        = 8;   // records walked per lookup

    // `capacity` is rounded up to a power of two (minimum 2).
    explicit DecisionLog(std::size_t capacity = DEFAULT_CAPACITY)
        : capacity_(round_up_pow2(capacity))
        , mask_(capacity_ - 1)
        , ring_(std::make_unique<Slot[]>(capacity_))
        , index_(std::make_unique<std::array<std::atomic<uint64_t>, 65536>[]>(2)) {
        for (int p = 0; p < 2; ++p)
            for (auto& t : index_[p]) t.store(0, std::memory_order_relaxed);
    }

    DecisionLog(const DecisionLog&)            = delete;
    DecisionLog& operator=(const DecisionLog&) = delete;

    std::size_t capacity() const noexcept { return capacity_; }

    // Append a record and make it the newest for (proto, local_port).
    // Returns its ticket, or 0 when the record was dropped (see header).
    uint64_t record(const DecisionRecord& r) noexcept {
        const uint64_t t = next_.fetch_add(1, std::memory_order_relaxed) + 1;   // tickets start at 1
        Slot& s = ring_[t & mask_];
        auto& head = index_[static_cast<int>(r.proto) & 1][r.local_port];

        uint64_t cur = s.seq.load(std::memory_order_relaxed);
        if ((cur & 1) || cur > 2 * t ||
            !s.seq.compare_exchange_strong(cur, 2 * t + 1, std::memory_order_relaxed,
                                           std::memory_order_relaxed)) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
        std::atomic_thread_fence(std::memory_order_release);

        uint64_t words[WORDS];
        std::memcpy(words, &r, sizeof(words));
        for (int i = 0; i < WORDS; ++i) s.words[i].store(words[i], std::memory_order_relaxed);
        const uint64_t prev = head.load(std::memory_order_acquire);
        s.prev.store(prev < t ? prev : 0, std::memory_order_relaxed);
        s.seq.store(2 * t + 2, std::memory_order_release);

        // Publish as the newest record for the port. A concurrent writer on
        // the same port with a newer ticket wins; ours stays in the ring but
        // drops out of the chain (rare: only the watchdog / pool paths write
        // off the strand).
        uint64_t h = prev;
        while (h < t && !head.compare_exchange_weak(h, t, std::memory_order_acq_rel,
                                                    std::memory_order_acquire)) {}
        written_.fetch_add(1, std::memory_order_relaxed);
        return t;
    }

    // Copy of the record with this ticket, or nullopt when it was evicted,
    // is being rewritten, or never existed.
    std::optional<DecisionRecord> read(uint64_t ticket) const noexcept {
        uint64_t prev = 0;
        DecisionRecord r;
        if (!read_slot(ticket, r, prev)) return std::nullopt;
        return r;
    }

    // Newest record for (proto, port) that satisfies `match`, walking back at
    // most MAX_CHAIN records of that port. Lock-free, any thread.
    template <typename Match>
    std::optional<DecisionRecord> find(decision_proto proto, uint16_t port, Match&& match) const {
        uint64_t t = index_[static_cast<int>(proto) & 1][port].load(std::memory_order_acquire);
        for (int hop = 0; hop < MAX_CHAIN && t != 0; ++hop) {
            DecisionRecord r;
            uint64_t prev = 0;
            if (!read_slot(t, r, prev)) return std::nullopt;     // evicted: so is everything older
            if (r.proto == proto && r.local_port == port && match(r)) return r;
            if (prev >= t) return std::nullopt;
            t = prev;
        }
        return std::nullopt;
    }

    // Newest record for (proto, port), any remote.
    std::optional<DecisionRecord> latest(decision_proto proto, uint16_t port) const {
        return find(proto, port, [](const DecisionRecord&) { return true; });
    }

    // TCP lookup by local port + IPv4 remote endpoint (host byte order).
    std::optional<DecisionRecord> find_tcp_v4(uint16_t local_port, uint32_t remote_ip,
                                              uint16_t remote_port) const {
        return find(decision_proto::tcp, local_port, [&](const DecisionRecord& r) {
            return !(r.flags & decision_flags::IPV6) && r.remote_addr[0] == remote_ip &&
                   r.remote_port == remote_port;
        });
    }

    struct stats {
        uint64_t written;
        uint64_t dropped;
        uint64_t capacity;
    };
    stats snapshot() const noexcept {
        return {written_.load(std::memory_order_relaxed), dropped_.load(std::memory_order_relaxed),
                capacity_};
    }

private:
    static constexpr int WORDS = sizeof(DecisionRecord) / sizeof(uint64_t);

    struct Slot {
        std::atomic<uint64_t> seq{0};    // 0 empty, 2t+1 writing ticket t, 2t+2 holds ticket t
        std::atomic<uint64_t> prev{0};   // previous ticket for the same port
        std::atomic<uint64_t> words[WORDS] = {};
    };

    static std::size_t round_up_pow2(std::size_t n) {
        std::size_t c = 2;
        while (c < n) c <<= 1;
        return c;
    }

    bool read_slot(uint64_t ticket, DecisionRecord& out, uint64_t& prev) const noexcept {
        if (ticket == 0) return false;
        const Slot& s = ring_[ticket & mask_];
        const uint64_t want = 2 * ticket + 2;
        if (s.seq.load(std::memory_order_acquire) != want) return false;
        uint64_t words[WORDS];
        for (int i = 0; i < WORDS; ++i) words[i] = s.words[i].load(std::memory_order_relaxed);
        prev = s.prev.load(std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_acquire);
        if (s.seq.load(std::memory_order_relaxed) != want) return false;
        std::memcpy(&out, words, sizeof(words));
        return true;
    }

    const std::size_t capacity_;
    const std::size_t mask_;
    std::unique_ptr<Slot[]> ring_;
    // [0] TCP, [1] UDP: local port -> newest ticket (0 = none).
    std::unique_ptr<std::array<std::atomic<uint64_t>, 65536>[]> index_;
    std::atomic<uint64_t> next_{0};
    std::atomic<uint64_t> written_{0};
    std::atomic<uint64_t> dropped_{0};
};

} // namespace clew
