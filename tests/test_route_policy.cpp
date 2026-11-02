// Route policy: the single verdict shared by the TCP SOCKET layer, the UDP
// SOCKET/NETWORK layers and the connection list. No driver, no admin rights.
//
// Covers rule.protocol and every dst_filter field (exclude/include CIDRs and
// ports), the global excludes, manual hijacks and process-tree inheritance,
// and that the NETWORK-side PolicyTable answers the same as the strand-side
// rule engine.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <format>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "config/types.hpp"
#include "process/flat_tree.hpp"
#include "rules/policy_table.hpp"
#include "rules/rule_engine_v3.hpp"
#include "rules/traffic_filter.hpp"

using namespace clew;

namespace {

struct TestEntry { std::string name; std::function<void()> fn; };
std::vector<TestEntry>& registry() {
    static std::vector<TestEntry> tests;
    return tests;
}

#define TEST(name) \
    static void test_##name(); \
    static const bool reg_##name = (registry().push_back({#name, test_##name}), true); \
    static void test_##name()

#define CHECK(expr) do { \
    if (!(expr)) { \
        std::ostringstream ss; \
        ss << __FILE__ << ":" << __LINE__ << ": " << #expr; \
        throw std::runtime_error(ss.str()); \
    } \
} while (0)

#define CHECK_REASON(actual, expected) do { \
    const auto a_ = (actual); \
    const auto e_ = (expected); \
    if (a_ != e_) { \
        std::ostringstream ss; \
        ss << __FILE__ << ":" << __LINE__ << ": " << #actual << " = " \
           << ip_exclude_reason_name(a_) << ", expected " << ip_exclude_reason_name(e_); \
        throw std::runtime_error(ss.str()); \
    } \
} while (0)

uint64_t g_next_psn = 1;

uint32_t add_entry(flat_tree& t, DWORD pid, DWORD parent_pid, const wchar_t* name) {
    FILETIME ft = {};
    uint64_t psn = g_next_psn++;
    uint64_t parent_psn = ROOT_PSN_SENTINEL;
    if (parent_pid != 0) {
        auto& sm = t.side_map();
        if (auto it = sm.find(parent_pid); it != sm.end()) parent_psn = it->second.psn;
    }
    uint32_t idx = t.add_entry(pid, parent_pid, psn, parent_psn, ft, name);
    if (parent_psn == ROOT_PSN_SENTINEL || parent_pid == 0) {
        t.mark_root(idx);
    } else {
        uint32_t pidx = t.find_by_pid_psn(parent_pid, parent_psn);
        if (pidx != INVALID_IDX) t.attach_child(pidx, idx);
        else t.mark_root(idx);
    }
    return idx;
}

AutoRule make_rule(std::string_view name, std::string_view process, std::string_view protocol,
                   bool hack_tree = false) {
    AutoRule r;
    r.id = std::format("rule_{}", name);
    r.name = name;
    r.enabled = true;
    r.process_name = process;
    r.hack_tree = hack_tree;
    r.proxy_group_id = 1;
    r.protocol = protocol;
    return r;
}

uint32_t ip(const char* s) { return CidrRange::ip_to_uint(s); }

constexpr bool TCP = false;
constexpr bool UDP = true;

}  // namespace

TEST(destination_order_and_reasons) {
    std::vector<CidrRange> global = {CidrRange::parse("10.0.0.0/8")};
    TrafficFilter f;
    f.exclude_cidrs = {CidrRange::parse("203.0.113.0/24")};
    f.exclude_ports = {PortRange::parse("22")};
    f.include_cidrs = {CidrRange::parse("198.51.100.0/24"), CidrRange::parse("203.0.113.0/24")};
    f.include_ports = {PortRange::parse("443"), PortRange::parse("8000-8100")};

    CHECK_REASON(evaluate_destination(global, &f, ip("10.1.2.3"), 443), IpExcludeReason::global);
    CHECK_REASON(evaluate_destination(global, &f, ip("203.0.113.5"), 443), IpExcludeReason::rule);
    CHECK_REASON(evaluate_destination(global, &f, ip("198.51.100.5"), 22), IpExcludeReason::rule_port);
    CHECK_REASON(evaluate_destination(global, &f, ip("192.0.2.5"), 443),
                 IpExcludeReason::include_cidr_miss);
    CHECK_REASON(evaluate_destination(global, &f, ip("198.51.100.5"), 80),
                 IpExcludeReason::include_port_miss);
    CHECK_REASON(evaluate_destination(global, &f, ip("198.51.100.5"), 443), IpExcludeReason::none);
    CHECK_REASON(evaluate_destination(global, &f, ip("198.51.100.5"), 8050), IpExcludeReason::none);

    // No rule (manual hijack): only the global list applies.
    CHECK_REASON(evaluate_destination(global, nullptr, ip("10.1.2.3"), 22), IpExcludeReason::global);
    CHECK_REASON(evaluate_destination(global, nullptr, ip("192.0.2.5"), 22), IpExcludeReason::none);

    // An empty filter adds nothing.
    TrafficFilter empty;
    CHECK_REASON(evaluate_destination(global, &empty, ip("192.0.2.5"), 1), IpExcludeReason::none);
}

TEST(rule_protocol_gates_each_transport) {
    flat_tree tree;
    add_entry(tree, 4, 0, L"System");
    add_entry(tree, 100, 4, L"tcp_only.exe");
    add_entry(tree, 200, 4, L"udp_only.exe");
    add_entry(tree, 300, 4, L"both.exe");

    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("t", "tcp_only.exe", "tcp"),
                           make_rule("u", "udp_only.exe", "udp"),
                           make_rule("b", "both.exe", "both")});
    engine.apply_auto_rules(tree);

    const auto dst = ip("198.51.100.1");
    CHECK_REASON(engine.route_reason(tree, 100, TCP, dst, 443), IpExcludeReason::none);
    CHECK_REASON(engine.route_reason(tree, 100, UDP, dst, 443), IpExcludeReason::protocol);
    // Before: a UDP-only rule still sent the process's TCP through the proxy.
    CHECK_REASON(engine.route_reason(tree, 200, TCP, dst, 443), IpExcludeReason::protocol);
    CHECK_REASON(engine.route_reason(tree, 200, UDP, dst, 443), IpExcludeReason::none);
    CHECK_REASON(engine.route_reason(tree, 300, TCP, dst, 443), IpExcludeReason::none);
    CHECK_REASON(engine.route_reason(tree, 300, UDP, dst, 443), IpExcludeReason::none);

    // route_reason agrees with the UDP SOCKET-layer gate.
    CHECK(engine.should_proxy_protocol(tree, 100, "udp") == false);
    CHECK(engine.should_proxy_protocol(tree, 200, "udp") == true);
}

TEST(include_ports_now_reach_the_data_path) {
    flat_tree tree;
    add_entry(tree, 4, 0, L"System");
    add_entry(tree, 100, 4, L"app.exe");

    auto rule = make_rule("app", "app.exe", "both");
    rule.dst_filter.include_ports = {PortRange::parse("443")};
    rule_engine_v3 engine;
    engine.set_auto_rules({rule});
    engine.apply_auto_rules(tree);

    const auto dst = ip("198.51.100.1");
    CHECK_REASON(engine.route_reason(tree, 100, TCP, dst, 443), IpExcludeReason::none);
    CHECK_REASON(engine.route_reason(tree, 100, TCP, dst, 22), IpExcludeReason::include_port_miss);
    CHECK_REASON(engine.ip_exclude_reason(tree, 100, dst, 53), IpExcludeReason::include_port_miss);
}

TEST(manual_hijack_ignores_rule_filters) {
    flat_tree tree;
    add_entry(tree, 4, 0, L"System");
    add_entry(tree, 100, 4, L"manual.exe");

    rule_engine_v3 engine;
    engine.set_default_exclude_cidrs({"192.168.0.0/16"});
    engine.manual_hijack(tree, 100, 0);

    CHECK_REASON(engine.route_reason(tree, 100, TCP, ip("192.168.1.1"), 80), IpExcludeReason::global);
    CHECK_REASON(engine.route_reason(tree, 100, TCP, ip("198.51.100.1"), 22), IpExcludeReason::none);
    CHECK_REASON(engine.route_reason(tree, 100, UDP, ip("198.51.100.1"), 22), IpExcludeReason::none);
}

TEST(tree_children_inherit_the_rule_filter) {
    flat_tree tree;
    add_entry(tree, 4, 0, L"System");
    add_entry(tree, 100, 4, L"edge.exe");
    add_entry(tree, 101, 100, L"renderer.exe");

    auto edge = make_rule("edge", "edge.exe", "tcp", /*hack_tree=*/true);
    edge.dst_filter.exclude_ports = {PortRange::parse("25")};
    edge.dst_filter.include_cidrs = {CidrRange::parse("198.51.100.0/24")};
    rule_engine_v3 engine;
    engine.set_auto_rules({edge});
    engine.apply_auto_rules(tree);

    CHECK_REASON(engine.route_reason(tree, 101, TCP, ip("198.51.100.9"), 25), IpExcludeReason::rule_port);
    CHECK_REASON(engine.route_reason(tree, 101, TCP, ip("192.0.2.9"), 443),
                 IpExcludeReason::include_cidr_miss);
    CHECK_REASON(engine.route_reason(tree, 101, TCP, ip("198.51.100.9"), 443), IpExcludeReason::none);
}

TEST(network_policy_table_matches_rule_engine) {
    flat_tree tree;
    add_entry(tree, 4, 0, L"System");
    add_entry(tree, 100, 4, L"game.exe");
    add_entry(tree, 200, 4, L"manual.exe");

    auto rule = make_rule("game", "game.exe", "udp");
    rule.dst_filter.exclude_cidrs = {CidrRange::parse("203.0.113.0/24")};
    rule.dst_filter.exclude_ports = {PortRange::parse("3478")};
    rule.dst_filter.include_ports = {PortRange::parse("3000-4000")};

    rule_engine_v3 engine;
    engine.set_default_exclude_cidrs({"10.0.0.0/8"});
    engine.set_auto_rules({rule});
    engine.apply_auto_rules(tree);
    engine.manual_hijack(tree, 200, 0);

    PolicyPublisher publisher;
    publisher.publish(engine.build_policy_table());
    PolicyReader reader(publisher);

    struct Probe { DWORD pid; const char* ip; uint16_t port; };
    const Probe probes[] = {
        {100, "10.0.0.1", 3500}, {100, "203.0.113.1", 3500}, {100, "198.51.100.1", 3478},
        {100, "198.51.100.1", 3500}, {100, "198.51.100.1", 53},
        {200, "10.0.0.1", 53}, {200, "198.51.100.1", 53},
    };
    for (const auto& p : probes) {
        const auto policy_id = engine.policy_id_for(tree, p.pid);
        CHECK_REASON(reader.evaluate(policy_id, ip(p.ip), p.port),
                     engine.ip_exclude_reason(tree, p.pid, ip(p.ip), p.port));
    }
}

TEST(rule_only_filter_keeps_loopback_direct) {
    TrafficFilter f;
    CHECK(!TrafficFilterEngine::should_proxy("127.0.0.1", 443, f));
    CHECK(TrafficFilterEngine::should_proxy("198.51.100.1", 443, f));
    f.exclude_ports = {PortRange::parse("22")};
    CHECK(!TrafficFilterEngine::should_proxy("198.51.100.1", 22, f));
}

int main() {
    int failed = 0;
    for (const auto& t : registry()) {
        try {
            t.fn();
            std::cout << "PASS " << t.name << "\n";
        } catch (const std::exception& e) {
            ++failed;
            std::cout << "FAIL " << t.name << ": " << e.what() << "\n";
        }
    }
    std::cout << (registry().size() - failed) << "/" << registry().size() << " passed\n";
    return failed == 0 ? 0 : 1;
}
