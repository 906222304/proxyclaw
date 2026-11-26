// Connection JSON built off the strand (src/projection/connection_rows.hpp),
// ROADMAP v0.14 #3. Every branch of the pre-#3 in-strand builder is pinned
// here: field set, proxy_status, route_reason, decision, decision_source.
// No driver, no admin rights, std + nlohmann only.

#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "projection/connection_rows.hpp"

using namespace clew;
using nlohmann::json;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

std::set<std::string> keys(const json& j) {
    std::set<std::string> k;
    for (auto it = j.begin(); it != j.end(); ++it) k.insert(it.key());
    return k;
}

const std::set<std::string> TCP_BASE = {"pid", "local_ip", "local_port", "remote_ip", "remote_port",
                                        "state", "dest", "hijacked", "pid_alive", "process_name",
                                        "proxy_status", "decision", "decision_source"};

connection_row tcp_row(uint32_t pid = 42) {
    connection_row r;
    r.pid         = pid;
    r.local_ip    = "10.0.0.2";
    r.local_port  = 50000;
    r.remote_ip   = "1.2.3.4";
    r.remote_port = 443;
    r.remote_addr = 0x01020304;
    r.state       = "ESTABLISHED";
    return r;
}

connection_row udp_row(uint32_t pid = 42, bool with_dest = false) {
    connection_row r;
    r.pid        = pid;
    r.local_ip   = "0.0.0.0";
    r.local_port = 5353;
    r.state      = "BOUND";
    if (with_dest) {
        r.remote_ip   = "8.8.8.8";
        r.remote_port = 53;
        r.remote_addr = 0x08080808;
    }
    return r;
}

connection_facts alive(bool hijacked, std::string name = "app.exe") {
    connection_facts f;
    f.pid_alive    = true;
    f.hijacked     = hijacked;
    f.process_name = std::move(name);
    return f;
}

DecisionRecord record(decision_verdict v, decision_reason why, uint32_t pid = 42) {
    DecisionRecord d;
    d.proto          = decision_proto::tcp;
    d.local_port     = 50000;
    d.remote_addr[0] = 0x01020304;
    d.remote_port    = 443;
    d.pid            = pid;
    d.psn            = 7;
    d.verdict        = v;
    d.reason         = why;
    d.source         = v == decision_verdict::proxied ? decision_source::rule : decision_source::none;
    d.group_id       = v == decision_verdict::proxied ? 3 : DECISION_NO_GROUP;
    d.policy_id      = v == decision_verdict::proxied ? 9 : 0;
    d.config_version = 5;
    d.at_ms          = 1700000000000;
    return d;
}

void test_tcp_recorded_golden() {
    auto row = tcp_row();
    row.record = record(decision_verdict::proxied, decision_reason::none);
    auto f = alive(true);
    f.rule_id = "rule-1";
    const json c = tcp_row_to_json(row, f);
    // nlohmann::json objects serialise with sorted keys: this is the exact
    // byte output /api/tcp produced for this row before v0.14 #3.
    const std::string golden =
        R"({"decision":{"at_ms":1700000000000,"config_version":5,"group":3,"pid":42,"psn":7,)"
        R"("reason":"none","rule_id":"rule-1","source":"rule","verdict":"proxied"},)"
        R"("decision_source":"recorded","dest":"1.2.3.4:443","hijacked":true,"local_ip":"10.0.0.2",)"
        R"("local_port":50000,"pid":42,"pid_alive":true,"process_name":"app.exe","proxy_status":"PROXIED",)"
        R"("remote_ip":"1.2.3.4","remote_port":443,"route_reason":"none","state":"ESTABLISHED"})";
    check(c.dump() == golden, "tcp recorded golden: " + c.dump());
}

void test_tcp_recorded_direct() {
    auto row = tcp_row();
    row.record = record(decision_verdict::direct, decision_reason::rule_exclude);
    const json c = tcp_row_to_json(row, alive(true));
    check(c["proxy_status"] == "IGNORED", "rule_exclude -> IGNORED");
    check(c["route_reason"] == "rule_exclude", "route_reason from record");
    check(c["decision"]["rule_id"].is_null(), "no policy -> rule_id null");
    check(c["decision"]["source"].is_null(), "source none -> null");
    check(c["decision"]["group"].is_null(), "no group -> null");
    check(!c["decision"].contains("late_verdict"), "late_verdict only for late");

    row.record = record(decision_verdict::direct, decision_reason::rule_exclude_child);
    row.record->source = decision_source::tree;
    auto child_f = alive(false);
    child_f.rule_id = "rule-parent";
    const json ce = tcp_row_to_json(row, child_f);
    check(ce["proxy_status"] == "IGNORED", "rule_exclude_child -> IGNORED");
    check(ce["route_reason"] == "rule_exclude_child", "rule_exclude_child route_reason");
    check(ce["decision"]["rule_id"] == "rule-parent", "rule_exclude_child keeps parent rule_id");

    row.record = record(decision_verdict::direct, decision_reason::not_proxied);
    check(tcp_row_to_json(row, alive(false))["proxy_status"] == "-", "not-proxied -> -");

    // Reasons that do not say whether the process was proxied use the
    // current state.
    for (auto why : {decision_reason::watchdog, decision_reason::pool_exhausted, decision_reason::ipv6}) {
        row.record = record(decision_verdict::direct, why);
        check(tcp_row_to_json(row, alive(true))["proxy_status"] == "IGNORED",
              std::string(decision_reason_name(why)) + " + hijacked -> IGNORED");
        check(tcp_row_to_json(row, alive(false))["proxy_status"] == "-",
              std::string(decision_reason_name(why)) + " + not hijacked -> -");
    }

    row.record = record(decision_verdict::direct, decision_reason::late);
    row.record->flags = decision_flags::LATE_PROXIED;
    json late = tcp_row_to_json(row, alive(false));
    check(late["proxy_status"] == "IGNORED", "late proxied -> IGNORED");
    check(late["decision"]["late_verdict"] == "proxied", "late_verdict proxied");
    row.record->flags = 0;
    late = tcp_row_to_json(row, alive(false));
    check(late["proxy_status"] == "-", "late direct, not hijacked -> -");
    check(late["decision"]["late_verdict"] == "direct", "late_verdict direct");
}

void test_tcp_listening() {
    auto row = tcp_row();
    row.state       = "LISTEN";
    row.remote_ip   = "0.0.0.0";
    row.remote_port = 0;
    row.listening   = true;
    json c = tcp_row_to_json(row, alive(true));
    check(c["proxy_status"] == "LISTEN", "hijacked listener -> LISTEN");
    check(c["decision"].is_null() && c["decision_source"] == "none", "listener has no decision");
    check(!c.contains("route_reason"), "listener has no route_reason");
    check(keys(c) == TCP_BASE, "listener field set");
    check(c["dest"] == "0.0.0.0:0", "listener dest");
    check(tcp_row_to_json(row, alive(false))["proxy_status"] == "-", "plain listener -> -");
    check(!needs_fallback(row, true), "listener never needs the fallback");
}

void test_tcp_recomputed() {
    auto row = tcp_row();
    check(needs_fallback(row, true), "no record + hijacked -> fallback");
    check(!needs_fallback(row, false), "no record + not hijacked -> no fallback");

    json c = tcp_row_to_json(row, alive(false));
    check(c["proxy_status"] == "-", "not hijacked -> -");
    check(c["decision"].is_null() && c["decision_source"] == "recomputed", "recomputed marker");
    check(!c.contains("route_reason"), "not hijacked has no route_reason");
    check(keys(c) == TCP_BASE, "not hijacked field set");

    auto f = alive(true);
    f.fallback_proxied = false;
    f.fallback_reason  = "global_exclude";
    c = tcp_row_to_json(row, f);
    check(c["proxy_status"] == "IGNORED" && c["route_reason"] == "global_exclude", "fallback excluded");

    f.fallback_proxied = true;
    f.fallback_reason  = "none";
    c = tcp_row_to_json(row, f);
    check(c["proxy_status"] == "PROXIED" && c["route_reason"] == "none", "fallback proxied");
    auto with_reason = TCP_BASE;
    with_reason.insert("route_reason");
    check(keys(c) == with_reason, "fallback field set");
}

void test_dead_pid() {
    auto row = tcp_row();
    connection_facts f;   // pid not in the tree
    f.process_name = "stale";
    json c = tcp_row_to_json(row, f);
    check(c["pid_alive"] == false && c["hijacked"] == false, "dead pid flags");
    check(c["process_name"] == "unknown", "dead pid -> unknown");
}

void test_udp() {
    // No destination, hijacked, no record: protocol gate.
    auto row = udp_row();
    auto f = alive(true);
    f.fallback_proxied = false;
    f.fallback_reason  = "rule_protocol";
    json c = udp_row_to_json(row, f);
    check(c["state"] == "BOUND", "udp state");
    check(c["remote_ip"] == "" && c["remote_port"] == 0 && c["dest"] == "", "udp without destination");
    check(c["proxy_status"] == "IGNORED" && c["route_reason"] == "rule_protocol", "udp protocol gate");
    check(c["decision_source"] == "recomputed", "udp recomputed");

    const std::string golden =
        R"({"decision":null,"decision_source":"recomputed","dest":"","hijacked":true,"local_ip":"0.0.0.0",)"
        R"("local_port":5353,"pid":42,"pid_alive":true,"process_name":"app.exe","proxy_status":"IGNORED",)"
        R"("remote_ip":"","remote_port":0,"route_reason":"rule_protocol","state":"BOUND"})";
    check(c.dump() == golden, "udp golden: " + c.dump());

    // With destination.
    row = udp_row(42, /*with_dest=*/true);
    f.fallback_proxied = true;
    f.fallback_reason  = "none";
    c = udp_row_to_json(row, f);
    check(c["dest"] == "8.8.8.8:53", "udp dest");
    check(c["proxy_status"] == "PROXIED", "udp fallback proxied");

    // Not hijacked: "-" and no route_reason.
    c = udp_row_to_json(row, alive(false));
    check(c["proxy_status"] == "-" && !c.contains("route_reason"), "udp not hijacked");

    // Recorded.
    row.record = record(decision_verdict::proxied, decision_reason::none);
    row.record->proto = decision_proto::udp;
    auto rf = alive(true);
    rf.rule_id = "r";
    c = udp_row_to_json(row, rf);
    check(c["decision_source"] == "recorded" && c["proxy_status"] == "PROXIED", "udp recorded");
    check(c["decision"]["rule_id"] == "r" && c["process_name"] == "app.exe", "udp recorded fields");
}

void test_record_fits_and_rows() {
    check(decision_record_fits(record(decision_verdict::proxied, decision_reason::none, 0), 42),
          "pid 0 record fits any row");
    check(decision_record_fits(record(decision_verdict::proxied, decision_reason::none, 42), 42),
          "same pid fits");
    check(!decision_record_fits(record(decision_verdict::proxied, decision_reason::none, 7), 42),
          "other pid does not fit");

    std::vector<connection_row> rows{tcp_row(1), tcp_row(2)};
    std::vector<connection_facts> facts{alive(false, "a.exe"), alive(false, "b.exe")};
    json arr = rows_to_json(rows, facts, /*is_udp=*/false);
    check(arr.is_array() && arr.size() == 2, "rows_to_json size");
    check(arr[1]["process_name"] == "b.exe" && arr[1]["pid"] == 2, "rows_to_json order");
    check(rows_to_json({}, {}, true).dump() == "[]", "empty -> []");
}

// v0.14 #4: `conflict` (current rules) and `estimate` (recomputed rows).
void test_conflict_and_estimate() {
    auto row = tcp_row();
    row.record = record(decision_verdict::proxied, decision_reason::none);
    auto f = alive(true);
    f.rule_id = "rule-1";
    json c = tcp_row_to_json(row, f);
    check(!c.contains("conflict") && !c.contains("estimate"), "no conflict -> no keys");

    f.conflict = std::make_shared<const rule_conflict>(make_rule_conflict(false, {"rule-1", "rule-2", "rule-3"}));
    c = tcp_row_to_json(row, f);
    check(c["conflict"].dump() == R"({"manual":false,"shadowed_rule_ids":["rule-2","rule-3"],"winner":"rule-1"})",
          "recorded conflict: " + c["conflict"].dump());
    check(!c.contains("estimate"), "recorded row has no estimate");

    // An empty conflict object is never emitted.
    f.conflict = std::make_shared<const rule_conflict>();
    check(!tcp_row_to_json(row, f).contains("conflict"), "empty conflict -> no key");

    // Manual hijack shadowing rules: winner null.
    f.conflict = std::make_shared<const rule_conflict>(make_rule_conflict(true, {"rule-1"}));
    c = tcp_row_to_json(row, f);
    check(c["conflict"]["manual"] == true && c["conflict"]["winner"].is_null() &&
          c["conflict"]["shadowed_rule_ids"] == json::array({"rule-1"}), "manual conflict");

    // Recomputed + proxied: estimate + conflict.
    row.record.reset();
    auto rf = alive(true);
    rf.fallback_proxied = true;
    rf.fallback_reason  = "none";
    rf.current_source   = decision_source::tree;
    rf.current_rule_id  = "rule-9";
    rf.conflict = std::make_shared<const rule_conflict>(make_rule_conflict(false, {"rule-9", "rule-1"}));
    c = tcp_row_to_json(row, rf);
    check(c["decision_source"] == "recomputed", "estimate row recomputed");
    check(c["estimate"].dump() == R"({"rule_id":"rule-9","source":"tree"})", "estimate: " + c["estimate"].dump());
    check(c["conflict"]["winner"] == "rule-9", "recomputed conflict");
    rf.current_source  = decision_source::manual;
    rf.current_rule_id.clear();
    c = tcp_row_to_json(row, rf);
    check(c["estimate"]["source"] == "manual" && c["estimate"]["rule_id"].is_null(), "manual estimate");

    // Not hijacked now: neither key even if facts carry them.
    auto nf = rf;
    nf.hijacked = false;
    c = tcp_row_to_json(row, nf);
    check(!c.contains("estimate") && !c.contains("conflict"), "not hijacked -> no keys");

    // Listening sockets never carry them.
    row.listening = true;
    check(keys(tcp_row_to_json(row, rf)) == TCP_BASE, "listener ignores conflict / estimate");

    // UDP: recorded and recomputed rows carry them too.
    auto urow = udp_row();
    c = udp_row_to_json(urow, rf);
    check(c["estimate"]["source"] == "manual" && c.contains("conflict"), "udp recomputed keys");
    urow.record = record(decision_verdict::proxied, decision_reason::none);
    urow.record->proto = decision_proto::udp;
    c = udp_row_to_json(urow, rf);
    check(!c.contains("estimate") && c.contains("conflict"), "udp recorded keys");
}

void test_resolve_tcp_decision_hook_mode() {
    DecisionLog log(64);
    auto rec = record(decision_verdict::proxied, decision_reason::none, 42);
    rec.local_port     = 50000;
    rec.remote_addr[0] = 0x01010101;   // 1.1.1.1
    rec.remote_port    = 80;
    log.record(rec);

    // Hook mode: OS table sees 127.0.0.1:<relay_port>, resolve_tcp_decision
    // matches (local_port, pid) and restores the real destination.
    connection_row hook_row;
    hook_row.pid         = 42;
    hook_row.local_ip    = "127.0.0.1";
    hook_row.local_port  = 50000;
    hook_row.remote_ip   = "127.0.0.1";
    hook_row.remote_port = 55123;
    hook_row.remote_addr = 0x7F000001u;
    hook_row.state       = "ESTABLISHED";
    resolve_tcp_decision(hook_row, &log, /*hook_relay_port=*/55123);
    check(hook_row.record.has_value(), "hook row matched recorded decision");
    check(hook_row.remote_ip == "1.1.1.1" && hook_row.remote_port == 80 &&
          hook_row.remote_addr == 0x01010101,
          "hook row restored original remote endpoint: " + hook_row.remote_ip + ":" +
              std::to_string(hook_row.remote_port));
    auto f = alive(true);
    f.rule_id = "rule-1";
    const json j = tcp_row_to_json(hook_row, f);
    check(j["proxy_status"] == "PROXIED" && j["decision_source"] == "recorded" &&
          j["dest"] == "1.1.1.1:80" && j["decision"]["rule_id"] == "rule-1",
          "hook row JSON reports PROXIED and real destination: " + j.dump());

    // Different PID on the same local port must not inherit PID 42's record.
    connection_row other_pid = hook_row;
    other_pid.pid         = 99;
    other_pid.remote_ip   = "127.0.0.1";
    other_pid.remote_port = 55123;
    other_pid.remote_addr = 0x7F000001u;
    other_pid.record.reset();
    resolve_tcp_decision(other_pid, &log, /*hook_relay_port=*/55123);
    check(!other_pid.record.has_value() && other_pid.remote_ip == "127.0.0.1",
          "hook row with mismatched PID stays unmatched");

    // Non-relay loopback port (e.g. local HTTP API) is NOT rewritten.
    connection_row local_api = hook_row;
    local_api.pid         = 42;
    local_api.remote_ip   = "127.0.0.1";
    local_api.remote_port = 18080;
    local_api.remote_addr = 0x7F000001u;
    local_api.record.reset();
    resolve_tcp_decision(local_api, &log, /*hook_relay_port=*/55123);
    check(!local_api.record.has_value() && local_api.remote_port == 18080,
          "non-relay loopback port is not rewritten");

    // WinDivert mode (hook_relay_port == 0) matches exact 4-tuple only.
    connection_row wd_row = tcp_row(42);
    wd_row.local_port  = 50000;
    wd_row.remote_ip   = "1.1.1.1";
    wd_row.remote_port = 80;
    wd_row.remote_addr = 0x01010101;
    resolve_tcp_decision(wd_row, &log, /*hook_relay_port=*/0);
    check(wd_row.record.has_value() && wd_row.record->verdict == decision_verdict::proxied,
          "windivert exact tuple match works");

    // Listening socket is never matched.
    connection_row listener = hook_row;
    listener.remote_ip   = "127.0.0.1";
    listener.remote_port = 55123;
    listener.remote_addr = 0x7F000001u;
    listener.listening   = true;
    listener.record.reset();
    resolve_tcp_decision(listener, &log, /*hook_relay_port=*/55123);
    check(!listener.record.has_value(), "listening socket ignored");
}

void test_hook_skip_reason_overrides_fallback() {
    auto row = tcp_row(77);
    auto f = alive(true, "StoreApp.exe");
    f.fallback_proxied = true;
    f.fallback_reason  = "none";
    f.hook_skip_reason = "hook_skip_restricted";
    f.current_source   = decision_source::rule;
    f.current_rule_id  = "rule-store";

    const json c = tcp_row_to_json(row, f);
    check(c["proxy_status"] == "IGNORED", "uninjected hook row must be IGNORED, not PROXIED");
    check(c["route_reason"] == "hook_skip_restricted", "route_reason names hook skip reason");
    check(c["decision_source"] == "recomputed", "recomputed row stays marked recomputed");

    auto urow = udp_row(77, false);
    const json uc = udp_row_to_json(urow, f);
    check(uc["proxy_status"] == "IGNORED" && uc["route_reason"] == "hook_skip_restricted",
          "UDP row also surfaces hook_skip_restricted");
}

void test_resolve_udp_decision_hook_mode() {
    DecisionLog log;

    // Hook mode IPv4 proxied UDP record fills remote_ip / remote_addr / remote_port.
    DecisionRecord d4 = record(decision_verdict::proxied, decision_reason::none, /*pid=*/42);
    d4.proto          = decision_proto::udp;
    d4.local_port     = 53000;
    d4.remote_addr[0] = 0x01010101;
    d4.remote_port    = 53;
    log.record(d4);

    connection_row hook4 = udp_row(42, /*with_dest=*/false);
    hook4.local_port = 53000;
    resolve_udp_decision(hook4, &log);
    check(hook4.record.has_value(), "hook udp v4 matched decision");
    check(hook4.remote_ip == "1.1.1.1" && hook4.remote_port == 53 &&
          hook4.remote_addr == 0x01010101,
          "hook udp v4 restored destination: " + hook4.remote_ip + ":" +
              std::to_string(hook4.remote_port));
    auto f = alive(true);
    f.rule_id = "rule-udp";
    const json j4 = udp_row_to_json(hook4, f);
    check(j4["proxy_status"] == "PROXIED" && j4["dest"] == "1.1.1.1:53" &&
          j4["decision"]["rule_id"] == "rule-udp",
          "hook udp v4 JSON reports PROXIED and real destination: " + j4.dump());

    // Hook mode IPv6 proxied UDP record formats RFC 5952 IPv6 address.
    DecisionRecord d6 = record(decision_verdict::proxied, decision_reason::none, /*pid=*/42);
    d6.proto          = decision_proto::udp;
    d6.local_port     = 53001;
    d6.flags          = decision_flags::IPV6;
    d6.remote_addr[3] = 0x26064700u;
    d6.remote_addr[2] = 0x47000000u;
    d6.remote_addr[1] = 0x00000000u;
    d6.remote_addr[0] = 0x00001111u;
    d6.remote_port    = 443;
    log.record(d6);

    connection_row hook6 = udp_row(42, /*with_dest=*/false);
    hook6.local_port = 53001;
    resolve_udp_decision(hook6, &log);
    check(hook6.remote_ip == "2606:4700:4700::1111" && hook6.remote_port == 443,
          "hook udp v6 restored RFC 5952 IPv6: " + hook6.remote_ip);

    // WinDivert row that already got remote_ip from UdpSessionTable is kept.
    connection_row wd = udp_row(42, /*with_dest=*/true);
    wd.local_port = 53000;
    resolve_udp_decision(wd, &log);
    check(wd.remote_ip == "8.8.8.8" && wd.remote_port == 53,
          "existing UdpSessionTable destination is not overwritten");

    // WinDivert BIND record (remote_port == 0) leaves remote_ip empty.
    DecisionRecord bind_rec = d4;
    bind_rec.local_port  = 53002;
    bind_rec.remote_port = 0;
    log.record(bind_rec);
    connection_row bind_row = udp_row(42, /*with_dest=*/false);
    bind_row.local_port = 53002;
    resolve_udp_decision(bind_row, &log);
    check(bind_row.record.has_value() && bind_row.remote_ip.empty() && bind_row.remote_port == 0,
          "UDP BIND record with remote_port 0 does not synthesize 0.0.0.0:0");

    // Direct/excluded decision does not populate remote_ip.
    DecisionRecord direct_rec = record(decision_verdict::direct, decision_reason::rule_exclude_port, 42);
    direct_rec.proto       = decision_proto::udp;
    direct_rec.local_port  = 53003;
    direct_rec.remote_port = 853;
    log.record(direct_rec);
    connection_row direct_row = udp_row(42, /*with_dest=*/false);
    direct_row.local_port = 53003;
    resolve_udp_decision(direct_row, &log);
    check(direct_row.record.has_value() && direct_row.remote_ip.empty(),
          "direct UDP decision leaves remote_ip empty");

    // Mismatched PID rejects the record.
    connection_row other = udp_row(99, /*with_dest=*/false);
    other.local_port = 53000;
    resolve_udp_decision(other, &log);
    check(!other.record.has_value() && other.remote_ip.empty(),
          "mismatched PID UDP record rejected");
}

} // namespace

int main() {
    test_tcp_recorded_golden();
    test_tcp_recorded_direct();
    test_tcp_listening();
    test_tcp_recomputed();
    test_dead_pid();
    test_udp();
    test_record_fits_and_rows();
    test_conflict_and_estimate();
    test_resolve_tcp_decision_hook_mode();
    test_hook_skip_reason_overrides_fallback();
    test_resolve_udp_decision_hook_mode();
    if (failures) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "connection_rows: all tests passed\n";
    return 0;
}
