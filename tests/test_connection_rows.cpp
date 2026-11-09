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
    if (failures) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "connection_rows: all tests passed\n";
    return 0;
}
