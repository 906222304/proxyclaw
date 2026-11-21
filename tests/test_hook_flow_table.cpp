// Hook mode: flow table bookkeeping and the pipe wire format.
#include "hook/hook_flow_table.hpp"
#include "hook/hook_protocol.hpp"

#include <cstddef>
#include <iostream>
#include <stdexcept>

using namespace std::chrono_literals;
using clew::hook::flow;
using clew::hook::flow_table;

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

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"a flow is taken once", taken_once},
        {"IPv4 and IPv6 ports are separate keys", families_are_separate},
        {"a newer connect from the same port replaces the older", newer_connect_replaces_older},
        {"stale flows expire", stale_flows_expire},
        {"wire layout is fixed", wire_layout},
    };
    int failures = 0;
    for (const auto& [name, test] : cases) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { ++failures; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    return failures ? 1 : 0;
}
