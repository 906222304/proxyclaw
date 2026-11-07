// v0.13.1 runtime-state regressions. No driver, no admin rights.
//
//   - per-process rule exclusions: engine-owned, keyed by (pid, psn), never
//     copied from the config, survive rule reloads, ignored for a recycled PID
//   - orphan registry: children keyed by (pid, psn) attach to the right
//     parent after flat_tree::compact() renumbers, expire, and are capped
//   - proxy group input validation (port range, host, type, credentials)
//   - IPv6 classification for SOCKET events, TCP :53 upstream selection

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <format>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "config/proxy_group_validation.hpp"
#include "config/types.hpp"
#include "core/ip_family.hpp"
#include "domain/orphan_registry.hpp"
#include "process/flat_tree.hpp"
#include "proxy/tcp_dns_upstream.hpp"
#include "rules/rule_engine_v3.hpp"

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

uint64_t g_next_psn = 1000;

// Insert (pid, psn) under parent_pid if the tree has it, else as a root.
uint32_t add(flat_tree& t, DWORD pid, DWORD parent_pid, const wchar_t* name,
             uint64_t psn = 0) {
    if (psn == 0) psn = g_next_psn++;
    uint64_t parent_psn = ROOT_PSN_SENTINEL;
    if (parent_pid != 0) {
        if (auto it = t.side_map().find(parent_pid); it != t.side_map().end())
            parent_psn = it->second.psn;
    }
    const uint32_t idx = t.add_entry(pid, parent_pid, psn, parent_psn, FILETIME{}, name);
    const uint32_t pidx = parent_psn == ROOT_PSN_SENTINEL
        ? INVALID_IDX : t.find_by_pid_psn(parent_pid, parent_psn);
    if (pidx != INVALID_IDX) t.attach_child(pidx, idx);
    else                     t.mark_root(idx);
    return idx;
}

AutoRule rule(std::string_view name, std::string_view process) {
    AutoRule r;
    r.id = std::format("rule_{}", name);
    r.name = name;
    r.enabled = true;
    r.process_name = process;
    r.hack_tree = true;
    r.proxy_group_id = 1;
    return r;
}

bool proxied(const flat_tree& t, DWORD pid) {
    const uint32_t idx = t.find_by_pid(pid);
    return idx != INVALID_IDX && t.at(idx).alive && t.at(idx).is_proxied();
}

uint64_t psn_of(const flat_tree& t, DWORD pid) { return t.at(t.find_by_pid(pid)).psn; }

} // namespace

// ---------------------------------------------------------------- exclusions

TEST(exclusion_applies_to_that_process_only) {
    flat_tree t;
    add(t, 100, 0, L"explorer.exe");
    add(t, 200, 100, L"chrome.exe");
    add(t, 201, 200, L"chrome.exe");
    rule_engine_v3 e;
    e.set_auto_rules({rule("c", "chrome.exe")});
    e.apply_auto_rules(t);
    CHECK(proxied(t, 200) && proxied(t, 201));

    CHECK(e.exclude_pid(t, "rule_c", 201) == rule_engine_v3::exclude_result::ok);
    e.apply_auto_rules(t);
    CHECK(proxied(t, 200));
    CHECK(!proxied(t, 201));
    CHECK(e.excluded_pids(t, "rule_c") == std::vector<DWORD>{201});

    CHECK(e.unexclude_pid("rule_c", 201));
    CHECK(!e.unexclude_pid("rule_c", 201));  // already gone -> 404 at the API
    e.apply_auto_rules(t);
    CHECK(proxied(t, 201));
}

TEST(exclusion_rejects_unknown_rule_and_dead_process) {
    flat_tree t;
    add(t, 200, 0, L"chrome.exe");
    rule_engine_v3 e;
    e.set_auto_rules({rule("c", "chrome.exe")});
    CHECK(e.exclude_pid(t, "rule_nope", 200) == rule_engine_v3::exclude_result::rule_not_found);
    CHECK(e.exclude_pid(t, "rule_c", 999) == rule_engine_v3::exclude_result::process_not_found);
    t.tombstone(200, psn_of(t, 200));
    CHECK(e.exclude_pid(t, "rule_c", 200) == rule_engine_v3::exclude_result::process_not_found);
    CHECK(e.exclusion_count() == 0);
}

TEST(exclusion_survives_config_reload_and_is_never_read_from_config) {
    flat_tree t;
    add(t, 200, 0, L"chrome.exe");
    rule_engine_v3 e;
    const auto cfg_rule = rule("c", "chrome.exe");
    e.set_auto_rules({cfg_rule});
    e.apply_auto_rules(t);
    CHECK(e.exclude_pid(t, "rule_c", 200) == rule_engine_v3::exclude_result::ok);

    // Any later config mutation reloads the rules from the config copy,
    // which carries no exclusion state at all.
    nlohmann::json j = cfg_rule;
    CHECK(!j.contains("excluded_pids"));
    e.set_auto_rules({j.get<AutoRule>()});
    e.apply_auto_rules(t);
    CHECK(!proxied(t, 200));
    CHECK(e.exclusion_count() == 1);

    // Rule deleted: its exclusions go with it, and a re-created rule with the
    // same id starts clean.
    e.set_auto_rules({});
    CHECK(e.exclusion_count() == 0);
    e.set_auto_rules({cfg_rule});
    e.apply_auto_rules(t);
    CHECK(proxied(t, 200));
}

TEST(exclusion_ignored_after_pid_reuse_with_lost_stop) {
    flat_tree t;
    add(t, 200, 0, L"chrome.exe");
    rule_engine_v3 e;
    e.set_auto_rules({rule("c", "chrome.exe")});
    CHECK(e.exclude_pid(t, "rule_c", 200) == rule_engine_v3::exclude_result::ok);
    e.apply_auto_rules(t);
    CHECK(!proxied(t, 200));

    // The excluded process exits, its STOP is lost, and PID 200 is reused by
    // a new chrome.exe: add_entry tombstones the stale entry. No
    // on_process_exit call, so only the PSN check can tell them apart.
    add(t, 200, 0, L"chrome.exe");
    e.apply_auto_rules(t);
    CHECK(proxied(t, 200));
    CHECK(e.excluded_pids(t, "rule_c").empty());

    // ETW-driven exit clears the stored pair as well.
    e.on_process_exit(200);
    CHECK(e.exclusion_count() == 0);
}

TEST(exclusion_dropped_on_process_exit) {
    flat_tree t;
    add(t, 200, 0, L"chrome.exe");
    add(t, 300, 0, L"chrome.exe");
    rule_engine_v3 e;
    e.set_auto_rules({rule("c", "chrome.exe")});
    CHECK(e.exclude_pid(t, "rule_c", 200) == rule_engine_v3::exclude_result::ok);
    CHECK(e.exclude_pid(t, "rule_c", 300) == rule_engine_v3::exclude_result::ok);
    t.tombstone(200, psn_of(t, 200));
    e.on_process_exit(200);
    CHECK(e.exclusion_count() == 1);
    CHECK(e.excluded_pids(t, "rule_c") == std::vector<DWORD>{300});
}

// ------------------------------------------------------------------ orphans

TEST(orphan_attaches_to_right_parent_after_compaction) {
    using clock = domain::orphan_registry::clock;
    flat_tree t;
    domain::orphan_registry orphans;
    add(t, 10, 0, L"a.exe");               // idx 0
    add(t, 40, 0, L"d0.exe");              // idx 1
    add(t, 41, 0, L"d1.exe");              // idx 2
    // Child whose parent (pid 20, psn 2) has not arrived yet.
    const uint32_t c_idx = t.add_entry(30, 20, 3, 2, FILETIME{}, L"child.exe");  // idx 3
    t.mark_root(c_idx);
    CHECK(orphans.park(2, 30, 3, clock::now()));
    for (DWORD pid = 60; pid < 64; ++pid) add(t, pid, 0, L"x.exe");             // idx 4..7

    // Two exits -> tombstones > 20% of alive -> compact() renumbers.
    CHECK(t.tombstone(40, psn_of(t, 40)));
    CHECK(t.tombstone(41, psn_of(t, 41)));
    CHECK(t.tombstone_count() == 0);                 // compaction ran
    CHECK(t.entries()[c_idx].pid != 30);             // old index now someone else
    const DWORD squatter = t.entries()[c_idx].pid;

    const uint32_t p_idx = t.add_entry(20, 0, 2, ROOT_PSN_SENTINEL, FILETIME{}, L"parent.exe");
    t.mark_root(p_idx);
    CHECK(orphans.drain(t, 2, p_idx) == 1);
    CHECK(orphans.size() == 0);
    CHECK(t.at(t.find_by_pid(30)).parent_index == p_idx);
    CHECK(t.at(t.find_by_pid(squatter)).parent_index == INVALID_IDX);
}

TEST(orphan_skips_recycled_pid) {
    using clock = domain::orphan_registry::clock;
    flat_tree t;
    domain::orphan_registry orphans;
    const uint32_t c = t.add_entry(50, 20, 5, 6, FILETIME{}, L"child.exe");
    t.mark_root(c);
    CHECK(orphans.park(6, 50, 5, clock::now()));
    // Child exits; PID 50 is reused by an unrelated process.
    t.tombstone(50, 5);
    add(t, 50, 0, L"other.exe", 7);
    const uint32_t p = t.add_entry(20, 0, 6, ROOT_PSN_SENTINEL, FILETIME{}, L"parent.exe");
    t.mark_root(p);
    CHECK(orphans.drain(t, 6, p) == 0);
    CHECK(t.at(t.find_by_pid(50)).parent_index == INVALID_IDX);
}

TEST(orphan_expiry_and_cap) {
    using clock = domain::orphan_registry::clock;
    flat_tree t;
    domain::orphan_registry orphans(2);
    const auto t0 = clock::now();
    const uint32_t a = t.add_entry(70, 20, 70, 9, FILETIME{}, L"a.exe");
    const uint32_t b = t.add_entry(71, 21, 71, 8, FILETIME{}, L"b.exe");
    t.mark_root(a);
    t.mark_root(b);
    CHECK(orphans.park(9, 70, 70, t0));
    CHECK(orphans.park(8, 71, 71, t0 + std::chrono::seconds(20)));
    CHECK(!orphans.park(9, 72, 72, t0));     // full
    CHECK(orphans.dropped() == 1);

    CHECK(orphans.expire(t, t0 + std::chrono::seconds(10)) == 1);  // only the old one
    CHECK(orphans.size() == 1);
    CHECK(orphans.expire_all(t) == 1);
    CHECK(orphans.size() == 0);
    CHECK(t.at(a).parent_index == INVALID_IDX);  // forgotten children stay roots
}

// -------------------------------------------------------- group validation

namespace {
std::string group_error(const nlohmann::json& body) {
    proxy_group_input in;
    const auto e = parse_proxy_group_input(body, in);
    return e ? e->field : std::string{};
}
} // namespace

TEST(group_port_range) {
    CHECK(group_error({{"port", 0}}) == "port");
    CHECK(group_error({{"port", 65536}}) == "port");
    CHECK(group_error({{"port", 70000}}) == "port");
    CHECK(group_error({{"port", -1}}) == "port");
    CHECK(group_error({{"port", "1080"}}) == "port");
    CHECK(group_error({{"port", 1080.5}}) == "port");
    CHECK(group_error({{"port", nullptr}}) == "port");
    proxy_group_input in;
    CHECK(!parse_proxy_group_input({{"port", 65535}}, in));
    CHECK(in.port && *in.port == 65535);
    CHECK(!parse_proxy_group_input({{"port", 1}}, in));
    CHECK(*in.port == 1);
}

TEST(group_host_normalised) {
    proxy_group_input in;
    CHECK(!parse_proxy_group_input({{"host", " [::1] "}}, in));
    CHECK(*in.host == "::1");
    CHECK(normalize_proxy_host("[2001:db8::1]") == "2001:db8::1");
    CHECK(normalize_proxy_host("proxy.local") == "proxy.local");
    CHECK(group_error({{"host", ""}}) == "host");
    CHECK(group_error({{"host", "[]"}}) == "host");
    CHECK(group_error({{"host", "10.0.0.1:1080"}}) == "host");
    CHECK(group_error({{"host", "a b"}}) == "host");
    CHECK(group_error({{"host", 5}}) == "host");
    CHECK(group_error({{"host", "2001:db8::1"}}).empty());
}

TEST(group_type_and_credentials) {
    proxy_group_input in;
    CHECK(!parse_proxy_group_input({{"type", "SOCKS5"}}, in));
    CHECK(*in.type == "socks5");
    CHECK(group_error({{"type", "http"}}) == "type");
    CHECK(group_error({{"type", "socks4"}}) == "type");
    CHECK(group_error({{"user", "alice"}}) == "user");
    CHECK(group_error({{"password", "x"}}) == "password");
    CHECK(group_error({{"user", ""}, {"password", ""}}).empty());
    CHECK(parse_proxy_group_input(nlohmann::json::array(), in).has_value());
    // A full create body as the UI sends it.
    CHECK(group_error({{"name", "g"}, {"host", "127.0.0.1"}, {"port", 7890},
                       {"type", "socks5"}, {"test_url", "http://1.1.1.1/"}}).empty());
}

// ------------------------------------------------------- IPv6, TCP :53 DNS

TEST(ipv6_socket_event_classification) {
    const uint32_t v4[4]     = {0x01020304u, 0x0000FFFFu, 0, 0};
    const uint32_t v6[4]     = {1, 0, 0, 0x20010db8u};
    const uint32_t zero[4]   = {0, 0, 0, 0};
    CHECK(!is_unmanaged_ipv6(false, v4));
    CHECK(!is_unmanaged_ipv6(true, v4));    // dual-stack socket, v4-mapped remote
    CHECK(is_unmanaged_ipv6(true, v6));
    CHECK(is_unmanaged_ipv6(true, zero));   // :: is not IPv4
    CHECK(!is_unmanaged_ipv6(false, v6));   // IPv4 layer: always managed
}

TEST(tcp_dns_upstream_selection) {
    CHECK(tcp_dns::parse_ipv4("1.1.1.1") == 0x01010101u);
    CHECK(!tcp_dns::parse_ipv4("1.1.1"));
    CHECK(!tcp_dns::parse_ipv4("1.1.1.256"));
    CHECK(!tcp_dns::parse_ipv4("1.1.1.1 "));
    CHECK(!tcp_dns::parse_ipv4("dns.google"));

    auto ep = tcp_dns::resolve("223.5.5.5", 53);
    CHECK(!ep.fallback && ep.ip == 0xDF050505u && ep.port == 53);
    ep = tcp_dns::resolve("9.9.9.9", 5353);
    CHECK(!ep.fallback && ep.port == 5353);
    for (const char* bad : {"dns.google", "2001:4860:4860::8888", "127.0.0.2", "0.0.0.0", ""}) {
        ep = tcp_dns::resolve(bad, 53);
        CHECK(ep.fallback && ep.ip == tcp_dns::kFallbackIp && ep.port == 53);
    }
    tcp_dns::publish(tcp_dns::resolve("1.0.0.1", 53));
    CHECK(tcp_dns::current().ip == 0x01000001u);
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
