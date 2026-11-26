// Hook mode: flow table, inject tracker, and the pipe wire format.
#include "hook/hook_flow_table.hpp"
#include "hook/hook_inject_tracker.hpp"
#include "hook/hook_protocol.hpp"

#include <cstddef>
#include <iostream>
#include <set>
#include <stdexcept>

using namespace std::chrono_literals;
using clew::hook::flow;
using clew::hook::flow_table;
using clew::hook::inject_tracker;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error(#expr); } while (false)

static const flow_table::clock::time_point t0{};

static flow v4(uint32_t ip, uint16_t port, uint32_t group = 1) {
    flow f;
    f.v4_host = ip;
    f.port = port;
    f.group_id = group;
    return f;
}

static void taken_once() {
    flow_table t;
    t.publish(false, 50000, v4(0x01010101, 443), t0);
    auto f = t.take(false, 50000, t0 + 1s);
    CHECK(f && f->v4_host == 0x01010101 && f->port == 443 && !f->ipv6);
    CHECK(!t.take(false, 50000, t0 + 1s));
    CHECK(t.snapshot().taken == 1);
}

static void families_are_separate() {
    flow_table t;
    flow six;
    six.ipv6 = true;
    six.v6[15] = 1;
    six.port = 80;
    t.publish(false, 40000, v4(0x08080808, 53), t0);
    t.publish(true, 40000, six, t0);
    auto a = t.take(true, 40000, t0);
    auto b = t.take(false, 40000, t0);
    CHECK(a && a->ipv6 && a->port == 80);
    CHECK(b && !b->ipv6 && b->port == 53);
}

static void newer_connect_replaces_older() {
    flow_table t;
    t.publish(false, 1234, v4(1, 1), t0);
    t.publish(false, 1234, v4(2, 2), t0 + 1s);
    auto f = t.take(false, 1234, t0 + 2s);
    CHECK(f && f->v4_host == 2);
    CHECK(t.snapshot().pending == 0);
}

static void stale_flows_expire() {
    flow_table t;
    t.publish(false, 1, v4(1, 1), t0);
    t.publish(false, 2, v4(2, 2), t0 + 20s);
    CHECK(!t.take(false, 1, t0 + flow_table::kMaxAge + 1s));
    t.prune(t0 + 20s + flow_table::kMaxAge + 1s);
    const auto s = t.snapshot();
    CHECK(s.pending == 0);
    CHECK(s.expired == 2);
}

static void wire_layout() {
    CHECK(sizeof(clew::hook::request) == 40);
    CHECK(sizeof(clew::hook::reply) == 16);
    CHECK(offsetof(clew::hook::request, dst) == 24);
    CHECK(offsetof(clew::hook::reply, relay_port) == 8);
}

static void child_survives_inflight_sweep() {
    inject_tracker tr;
    const inject_tracker::key parent{100, 1};
    const inject_tracker::key child{200, 2};

    // Sweep 1 captures {parent}; while it runs, decide_child() registers child.
    CHECK(tr.publish_wanted({parent}) == 1);
    const auto b1 = tr.take_wanted();
    CHECK(b1.gen == 1);
    tr.mark_child(child);
    tr.mark_swept(parent, b1.gen);
    tr.prune({parent}, b1.gen);
    CHECK(tr.is_done(parent));
    CHECK(tr.is_done(child));

    // Sweep 2 sees both: child is already done (not re-injected) and kept.
    CHECK(tr.publish_wanted({parent, child}) == 2);
    const auto b2 = tr.take_wanted();
    CHECK(tr.is_done(child));
    tr.prune({parent, child}, b2.gen);
    CHECK(tr.is_done(child));

    // Sweep 3 after child exits: child's generation (2) <= 3, so it is pruned.
    CHECK(tr.publish_wanted({parent}) == 3);
    const auto b3 = tr.take_wanted();
    tr.prune({parent}, b3.gen);
    CHECK(!tr.is_done(child));
    CHECK(tr.is_done(parent) && tr.done_count() == 1);
}

static void child_failed_enables_sweep_fallback() {
    inject_tracker tr;
    const inject_tracker::key parent{100, 1};
    const inject_tracker::key child{200, 2};

    tr.mark_swept(parent, 1);
    tr.mark_child(child);
    CHECK(tr.is_done(child));
    CHECK(tr.clear_child(child));
    CHECK(!tr.is_done(child));
    // Idempotent: a second clear_child must not report true again.
    CHECK(!tr.clear_child(child));
    // Non-child (sweep-injected) entries cannot be cleared via clear_child.
    CHECK(!tr.clear_child(parent));
    CHECK(tr.is_done(parent));
}

static void status_tracking_and_counts() {
    using clew::hook::inject_status;
    inject_tracker tr;
    const inject_tracker::key p1{101, 1};
    const inject_tracker::key p2{102, 2};
    const inject_tracker::key p3{103, 3};
    const inject_tracker::key p4{104, 4};

    CHECK(tr.publish_wanted({p1, p2, p3, p4}) == 1);
    const auto b = tr.take_wanted();
    tr.mark_swept(p1, b.gen, inject_status::injected);
    tr.mark_swept(p2, b.gen, inject_status::restricted);
    tr.mark_swept(p3, b.gen, inject_status::signed_only);
    tr.mark_swept(p4, b.gen, inject_status::failed);

    CHECK(tr.status_of(p1) == inject_status::injected);
    CHECK(tr.status_of(p2) == inject_status::restricted);
    CHECK(tr.status_of(p3) == inject_status::signed_only);
    CHECK(tr.status_of(p4) == inject_status::failed);
    CHECK(!tr.status_of({999, 9}).has_value());

    const auto c = tr.count_statuses();
    CHECK(c.injected == 1 && c.restricted == 1 && c.signed_only == 1 && c.failed == 1 &&
          c.wow64 == 0 && c.open_failed == 0);

    const auto snap = tr.snapshot_statuses();
    CHECK(snap.size() == 4 && snap.at(p2) == inject_status::restricted);

    CHECK(clew::hook::hook_skip_reason_name(inject_status::injected) == nullptr);
    CHECK(clew::hook::hook_skip_reason_name(inject_status::pending) == nullptr);
    CHECK(std::string(clew::hook::hook_skip_reason_name(inject_status::restricted)) == "hook_skip_restricted");
    CHECK(std::string(clew::hook::hook_skip_reason_name(inject_status::signed_only)) == "hook_skip_signed_only");
    CHECK(std::string(clew::hook::hook_skip_reason_name(inject_status::wow64)) == "hook_skip_wow64");
    CHECK(std::string(clew::hook::hook_skip_reason_name(inject_status::open_failed)) == "hook_skip_open_failed");
    CHECK(std::string(clew::hook::hook_skip_reason_name(inject_status::failed)) == "hook_skip_failed");

    // Pruning a departed skipped process removes it from counts and snapshot.
    CHECK(tr.publish_wanted({p1}) == 2);
    const auto b2 = tr.take_wanted();
    CHECK(tr.prune({p1}, b2.gen));
    const auto c2 = tr.count_statuses();
    CHECK(c2.injected == 1 && c2.restricted == 0 && c2.signed_only == 0 && c2.failed == 0);
}

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"a flow is taken once", taken_once},
        {"IPv4 and IPv6 ports are separate keys", families_are_separate},
        {"a newer connect from the same port replaces the older", newer_connect_replaces_older},
        {"stale flows expire", stale_flows_expire},
        {"wire layout is fixed", wire_layout},
        {"child registered during sweep is not pruned prematurely", child_survives_inflight_sweep},
        {"child_failed clears only child entries for sweep fallback", child_failed_enables_sweep_fallback},
        {"inject_status tracking, snapshots, and skip reason mapping", status_tracking_and_counts},
    };
    int failures = 0;
    for (const auto& [name, test] : cases) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { ++failures; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    return failures ? 1 : 0;
}
