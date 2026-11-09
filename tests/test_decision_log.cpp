// Per-connection decision record (src/core/decision_log.hpp), ROADMAP v0.14 #2.
// No driver, no admin rights, std only.

#include <atomic>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "core/decision_log.hpp"

using namespace clew;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

DecisionRecord tcp(uint16_t port, uint32_t remote, uint16_t rport, uint32_t pid,
                   decision_verdict v = decision_verdict::proxied,
                   decision_reason why = decision_reason::none) {
    DecisionRecord r;
    r.proto          = decision_proto::tcp;
    r.local_port     = port;
    r.remote_addr[0] = remote;
    r.remote_port    = rport;
    r.pid            = pid;
    r.psn            = 1000 + pid;
    r.verdict        = v;
    r.reason         = why;
    r.group_id       = v == decision_verdict::proxied ? 0 : DECISION_NO_GROUP;
    r.at_ms          = decision_now_ms();
    return r;
}

void record_and_lookup() {
    DecisionLog log(64);
    check(log.capacity() == 64, "capacity is the requested power of two");
    check(!log.latest(decision_proto::tcp, 5000), "empty log has nothing");

    auto r = tcp(5000, 0x01010101, 80, 42);
    r.source         = decision_source::rule;
    r.policy_id      = 7;
    r.config_version = 3;
    const auto t = log.record(r);
    check(t != 0, "record returns a ticket");

    auto got = log.find_tcp_v4(5000, 0x01010101, 80);
    check(got.has_value(), "lookup by local port + remote endpoint");
    if (got) {
        check(got->pid == 42 && got->psn == 1042, "pid + psn round trip");
        check(got->verdict == decision_verdict::proxied, "verdict round trip");
        check(got->source == decision_source::rule && got->policy_id == 7, "source + policy");
        check(got->config_version == 3, "config version round trip");
    }
    check(!log.find_tcp_v4(5000, 0x01010101, 443), "other remote port does not match");
    check(!log.find_tcp_v4(5000, 0x08080808, 80), "other remote address does not match");
    check(!log.find_tcp_v4(5001, 0x01010101, 80), "other local port does not match");
    check(!log.latest(decision_proto::udp, 5000), "TCP and UDP indexes are separate");
    check(log.read(t).has_value(), "read by ticket");
}

void port_reuse_walks_chain() {
    DecisionLog log(64);
    log.record(tcp(6000, 0x01010101, 80, 1, decision_verdict::proxied));
    log.record(tcp(6000, 0x01000001, 443, 2, decision_verdict::direct,
                   decision_reason::rule_exclude_port));
    log.record(tcp(6000, 0x08080808, 53, 3, decision_verdict::direct, decision_reason::global_exclude));

    auto newest = log.latest(decision_proto::tcp, 6000);
    check(newest && newest->pid == 3, "latest is the newest record for the port");
    auto older = log.find_tcp_v4(6000, 0x01010101, 80);
    check(older && older->pid == 1 && older->verdict == decision_verdict::proxied,
          "older connection on a reused port is still found");
    auto mid = log.find_tcp_v4(6000, 0x01000001, 443);
    check(mid && mid->reason == decision_reason::rule_exclude_port, "middle of the chain");

    // Same 4-tuple reused: the newest record wins.
    log.record(tcp(6000, 0x01010101, 80, 9, decision_verdict::direct, decision_reason::late));
    auto again = log.find_tcp_v4(6000, 0x01010101, 80);
    check(again && again->pid == 9 && again->reason == decision_reason::late,
          "same tuple reused: newest decision wins");
}

void wraparound_evicts_oldest() {
    DecisionLog log(16);
    for (uint16_t p = 1; p <= 16; ++p) log.record(tcp(p, 0x01010101, 80, p));
    check(log.find_tcp_v4(1, 0x01010101, 80).has_value(), "full ring keeps every record");

    // Four more: ports 1..4 are overwritten.
    for (uint16_t p = 17; p <= 20; ++p) log.record(tcp(p, 0x01010101, 80, p));
    for (uint16_t p = 1; p <= 4; ++p)
        check(!log.latest(decision_proto::tcp, p).has_value(),
              "evicted record for port " + std::to_string(p) + " is gone");
    for (uint16_t p = 5; p <= 20; ++p)
        check(log.latest(decision_proto::tcp, p).has_value(),
              "surviving record for port " + std::to_string(p));
    const auto s = log.snapshot();
    check(s.written == 20 && s.dropped == 0, "counters after wrap");

    // Many laps: the index of an evicted port must not resolve to a newer
    // record that landed in the same slot for another port.
    for (int i = 0; i < 1000; ++i) log.record(tcp(static_cast<uint16_t>(100 + (i % 7)), 0x02020202, 443, 7));
    check(!log.latest(decision_proto::tcp, 20).has_value(), "evicted after many laps");
    check(log.latest(decision_proto::tcp, 100).has_value(), "recent port present after many laps");
}

void chain_stops_at_evicted() {
    DecisionLog log(8);
    log.record(tcp(7000, 0x01010101, 80, 1));            // will be evicted
    for (uint16_t i = 0; i < 8; ++i) log.record(tcp(static_cast<uint16_t>(8000 + i), 0x01010101, 80, 2));
    log.record(tcp(7000, 0x01010101, 443, 3));           // newest for 7000, prev evicted
    check(!log.find_tcp_v4(7000, 0x01010101, 80).has_value(), "evicted chain link is not followed");
    check(log.find_tcp_v4(7000, 0x01010101, 443).has_value(), "head still found");
}

void udp_and_ipv6() {
    DecisionLog log(32);
    DecisionRecord u;
    u.proto      = decision_proto::udp;
    u.local_port = 5353;
    u.pid        = 77;
    u.verdict    = decision_verdict::proxied;
    u.source     = decision_source::manual;
    log.record(u);
    auto got = log.latest(decision_proto::udp, 5353);
    check(got && got->pid == 77 && got->source == decision_source::manual, "UDP keyed by local port");

    DecisionRecord v6 = tcp(9000, 0x01010101, 80, 5, decision_verdict::direct, decision_reason::ipv6);
    v6.flags |= decision_flags::IPV6;
    v6.remote_addr[1] = 0x12345678;
    log.record(v6);
    check(!log.find_tcp_v4(9000, 0x01010101, 80).has_value(),
          "IPv6 record never matches an IPv4 lookup with the same low word");
    auto any = log.latest(decision_proto::tcp, 9000);
    check(any && any->reason == decision_reason::ipv6, "IPv6 record readable");
}

void names() {
    check(std::string(decision_reason_name(decision_reason::unknown_pid)) == "unknown-pid", "reason name");
    check(std::string(decision_reason_name(decision_reason::rule_exclude_port)) == "rule_exclude_port",
          "route reason keeps the traffic_filter name");
    check(std::string(decision_reason_name(decision_reason::pool_exhausted)) == "pool_exhausted", "pool");
    check(std::string(decision_source_name(decision_source::tree)) == "tree", "source name");
}

// Writers on several threads (strand + injector + worker in production) and
// readers polling: every record a reader accepts must be internally
// consistent (no torn copy), and nothing may crash or deadlock.
void concurrent_writers_and_readers() {
    DecisionLog log(256);
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> torn{0}, hits{0};
    constexpr int WRITERS = 3;
    constexpr int PER     = 200000;

    auto writer = [&](int w) {
        for (int i = 0; i < PER; ++i) {
            const auto port = static_cast<uint16_t>(1000 + (i % 64));
            DecisionRecord r = tcp(port, static_cast<uint32_t>(i), 80, static_cast<uint32_t>(w * PER + i));
            // Self-check fields derived from the pid.
            r.psn            = r.pid * 3ull + 1;
            r.config_version = r.pid ^ 0xABCDEFull;
            r.remote_port    = static_cast<uint16_t>(r.pid & 0xFFFF);
            log.record(r);
        }
    };
    auto reader = [&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            for (uint16_t port = 1000; port < 1064; ++port) {
                auto r = log.latest(decision_proto::tcp, port);
                if (!r) continue;
                hits.fetch_add(1, std::memory_order_relaxed);
                if (r->psn != r->pid * 3ull + 1 || r->config_version != (r->pid ^ 0xABCDEFull) ||
                    r->remote_port != static_cast<uint16_t>(r->pid & 0xFFFF) || r->local_port != port)
                    torn.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    std::vector<std::thread> ts;
    for (int i = 0; i < 2; ++i) ts.emplace_back(reader);
    std::vector<std::thread> ws;
    for (int w = 0; w < WRITERS; ++w) ws.emplace_back(writer, w);
    for (auto& t : ws) t.join();
    stop = true;
    for (auto& t : ts) t.join();

    const auto s = log.snapshot();
    check(torn.load() == 0, "no torn record accepted (" + std::to_string(torn.load()) + ")");
    check(s.written + s.dropped == static_cast<uint64_t>(WRITERS) * PER, "every record written or counted dropped");
    check(hits.load() > 0, "readers saw records");
    for (uint16_t port = 1000; port < 1064; ++port)
        check(log.latest(decision_proto::tcp, port).has_value() || s.dropped > 0,
              "quiescent: port " + std::to_string(port) + " has a record");
    std::cout << "concurrent: written=" << s.written << " dropped=" << s.dropped
              << " reader_hits=" << hits.load() << "\n";
}

} // namespace

int main() {
    record_and_lookup();
    port_reuse_walks_chain();
    wraparound_evicts_oldest();
    chain_stops_at_evicted();
    udp_and_ipv6();
    names();
    concurrent_writers_and_readers();
    if (failures) {
        std::cerr << failures << " decision_log check(s) failed\n";
        return 1;
    }
    std::cout << "decision_log: all checks passed\n";
    return 0;
}
