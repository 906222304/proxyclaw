// Unit tests for v0.18 #2 resource caps:
//   - session_limiter (active/pending permits, RAII move semantics, overflow counters, concurrency)
//   - UdpSessionTable (max_sessions cap, opportunistic expiry cleanup, updates at cap)
//   - ipv6_flow_table (max_flows cap, expired-drain reclamation, overwrite at cap)
//   - ipv6_tcp_gate (expired verdict slot pruning)
//   - hook::flow_table (max_pending cap, expired reclamation, overwrite at cap)
//   - UdpQueueLimits (max_ports default)
//
// Pure C++23, no driver / admin rights required.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/ipv6_flow_table.hpp"
#include "core/ipv6_gate.hpp"
#include "hook/hook_flow_table.hpp"
#include "proxy/session_limiter.hpp"
#include "udp/udp_flow.hpp"
#include "udp/udp_session_table.hpp"

using namespace clew;
using namespace std::chrono_literals;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

struct fake_clock {
    using duration   = std::chrono::nanoseconds;
    using rep        = duration::rep;
    using period     = duration::period;
    using time_point = std::chrono::time_point<fake_clock>;
    static constexpr bool is_steady = true;
    static time_point now() { return time_point{}; }
};

void session_limiter_enforces_caps_and_raii() {
    session_limiter lim(/*max_active=*/2, /*max_pending=*/1);
    {
        auto a1 = lim.try_acquire_active();
        auto a2 = lim.try_acquire_active();
        auto a3 = lim.try_acquire_active();
        check(static_cast<bool>(a1) && static_cast<bool>(a2), "active permits up to cap succeed");
        check(!static_cast<bool>(a3), "active permit beyond cap rejected");

        auto p1 = lim.try_acquire_pending();
        auto p2 = lim.try_acquire_pending();
        check(static_cast<bool>(p1), "pending permit up to cap succeeds");
        check(!static_cast<bool>(p2), "pending permit beyond cap rejected");

        // Move semantics preserve exact count (no double release).
        auto a1_moved = std::move(a1);
        check(!static_cast<bool>(a1) && static_cast<bool>(a1_moved), "move transfers ownership");
        auto s = lim.stats();
        check(s.active == 2 && s.active_peak == 2 && s.rejected_active == 1, "active stats exact");
        check(s.pending == 1 && s.pending_peak == 1 && s.rejected_pending == 1, "pending stats exact");

        p1.release();
        check(!static_cast<bool>(p1), "explicit release clears permit");
        check(lim.stats().pending == 0, "pending drops to 0 after release");
        auto p3 = lim.try_acquire_pending();
        check(static_cast<bool>(p3), "pending slot reusable after release");
    }
    const auto s = lim.stats();
    check(s.active == 0 && s.pending == 0, "all permits released on scope exit");
    check(s.active_peak == 2 && s.pending_peak == 1, "peaks preserved");
    check(s.rejected_active == 1 && s.rejected_pending == 1, "rejection counts preserved");
}

void session_limiter_multithreaded_bound() {
    session_limiter lim(/*max_active=*/8, /*max_pending=*/4);
    std::atomic<bool> violated{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 6; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 2000; ++i) {
                auto a = lim.try_acquire_active();
                if (a) {
                    if (lim.stats().active > 8) violated.store(true);
                    auto p = lim.try_acquire_pending();
                    if (p && lim.stats().pending > 4) violated.store(true);
                }
            }
        });
    }
    for (auto& th : threads) th.join();
    const auto s = lim.stats();
    check(!violated.load(), "never exceeded cap concurrently");
    check(s.active == 0 && s.pending == 0, "no permit leak after concurrent churn");
    check(s.active_peak <= 8 && s.pending_peak <= 4, "peaks bounded by caps");
}

void udp_session_table_enforces_cap_and_reclaims_expired() {
    UdpSessionTable tbl(/*max_sessions=*/2);
    const auto t0 = std::chrono::steady_clock::now();

    UdpSession s1{};
    s1.app_src_port = 50001;
    s1.has_v4 = true;
    s1.last_active = t0;

    UdpSession s2 = s1;
    s2.app_src_port = 50002;
    s2.last_active = t0 + 100s;

    UdpSession s3 = s1;
    s3.app_src_port = 50003;
    s3.last_active = t0 + 100s;

    check(tbl.upsert(50001, s1, t0), "first insert succeeds");
    check(tbl.upsert(50002, s2, t0 + 100s), "second insert succeeds");
    // Full with fresh entries -> rejected.
    check(!tbl.upsert(50003, s3, t0 + 100s), "third insert rejected at cap");
    check(tbl.stats().rejected_cap == 1 && tbl.stats().peak == 2, "rejection and peak tracked");

    // Updating an existing port succeeds even when full.
    s2.has_v6 = true;
    check(tbl.upsert(50002, s2, t0 + 100s), "update of existing port allowed at cap");

    // Once s1 expires (>120s), opportunistic cleanup makes room for s3.
    s3.last_active = t0 + 130s;
    check(tbl.upsert(50003, s3, t0 + 130s), "opportunistic expiry allows new insert");
    check(!tbl.lookup(50001).has_value() && tbl.lookup(50003).has_value(), "expired entry reclaimed");
    check(tbl.stats().active == 2 && tbl.stats().max_sessions == 2, "stats report active & cap");
}

void ipv6_flow_table_enforces_cap_and_reclaims_drained() {
    ipv6_flow_table<fake_clock> tbl(10s, /*max_flows=*/2);
    const fake_clock::time_point t0{};
    v6_flow f{};
    f.remote[0] = 0x20;
    f.remote_port = 443;

    const auto id1 = tbl.publish(60001, f, t0);
    const auto id2 = tbl.publish(60002, f, t0);
    check(id1 != 0 && id2 != 0, "publish up to cap succeeds");
    check(tbl.publish(60003, f, t0) == 0, "publish beyond cap returns 0");
    check(tbl.snapshot().rejected_cap == 1 && tbl.snapshot().peak == 2, "v6 rejection & peak tracked");

    // Overwriting an existing port succeeds even at cap.
    check(tbl.publish(60002, f, t0) != 0, "overwrite of existing port succeeds at cap");

    // Retiring port 60001 and advancing past drain allows opportunistic reclaim.
    tbl.retire(60001, id1, t0);
    check(tbl.publish(60003, f, t0 + 5s) == 0, "not yet drained -> still rejected");
    check(tbl.publish(60003, f, t0 + 10s) != 0, "expired drained flow reclaimed");
    check(!tbl.maybe_ours(60001) && tbl.maybe_ours(60003), "active flags synced on reclaim");
}

void ipv6_gate_prunes_expired_slots() {
    ipv6_tcp_gate<int, fake_clock> gate(2s);
    const fake_clock::time_point t0{};
    for (uint16_t p = 1; p <= ipv6_tcp_gate<int, fake_clock>::kPruneSlotsAbove; ++p) {
        gate.decide(p, v6_verdict::allow, t0);
    }
    check(gate.slot_count() == ipv6_tcp_gate<int, fake_clock>::kPruneSlotsAbove,
          "slots populated to threshold");
    // After TTL, the next decide() triggers pruning of all stale slots.
    gate.decide(50000, v6_verdict::block, t0 + 5s);
    check(gate.slot_count() == 1, "expired gate slots pruned on overflow threshold");
}

void hook_flow_table_enforces_cap_and_reclaims_expired() {
    hook::flow_table tbl(/*max_pending=*/2);
    const hook::flow_table::clock::time_point t0{};
    hook::flow f{};
    f.v4_host = 0x01010101;
    f.port = 443;

    check(tbl.publish(false, 40001, f, t0), "hook flow 1 succeeds");
    check(tbl.publish(false, 40002, f, t0 + 10s), "hook flow 2 succeeds");
    check(!tbl.publish(false, 40003, f, t0 + 10s), "hook flow 3 rejected at cap");
    check(tbl.publish(false, 40002, f, t0 + 11s), "overwrite on same port allowed at cap");

    // Advance past kMaxAge for port 40001 -> reclaimed on next publish.
    check(tbl.publish(false, 40003, f, t0 + hook::flow_table::kMaxAge + 1s),
          "expired hook flow reclaimed on publish");
    const auto s = tbl.snapshot();
    check(s.pending == 2 && s.max_pending == 2 && s.peak == 2 && s.rejected_cap == 1 && s.expired == 1,
          "hook flow_table counters exact");
}

void udp_queue_limits_include_max_ports() {
    UdpQueueLimits lim;
    check(lim.max_ports > 0 && lim.max_ports <= 4096, "UdpQueueLimits::max_ports is bounded");
}

} // namespace

int main() {
    session_limiter_enforces_caps_and_raii();
    session_limiter_multithreaded_bound();
    udp_session_table_enforces_cap_and_reclaims_expired();
    ipv6_flow_table_enforces_cap_and_reclaims_drained();
    ipv6_gate_prunes_expired_slots();
    hook_flow_table_enforces_cap_and_reclaims_expired();
    udp_queue_limits_include_max_ports();
    if (failures) {
        std::cerr << "resource_caps_tests: " << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "resource_caps_tests: all passed\n";
    return 0;
}
