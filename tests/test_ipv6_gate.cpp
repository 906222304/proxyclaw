// IPv6 block bookkeeping and packet building (src/core/ipv6_gate.hpp,
// src/core/ip_family.hpp). No driver, no admin rights.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "core/ip_family.hpp"
#include "core/ipv6_flow_table.hpp"
#include "core/ipv6_gate.hpp"

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
using tp = fake_clock::time_point;

void verdicts_cover_syns_until_ttl_or_close() {
    ipv6_tcp_gate<int, fake_clock> g(2s);
    const tp t0{};
    check(g.lookup(5000, t0) == v6_verdict::none, "unknown port has no verdict");
    check(g.decide(5000, v6_verdict::block, t0).empty(), "nothing parked");
    check(g.lookup(5000, t0 + 1s) == v6_verdict::block, "verdict within ttl");
    check(g.lookup(5000, t0 + 3s) == v6_verdict::block, "a refused retry slides the block verdict");
    check(g.lookup(5000, t0 + 5500ms) == v6_verdict::none, "block verdict expires ttl after the last retry");
    // Windows retries a refused SYN every 0.5 s for ~2 s: all stay refused.
    g.decide(5001, v6_verdict::block, t0);
    for (int i = 1; i <= 8; ++i)
        check(g.lookup(5001, t0 + std::chrono::milliseconds(500 * i)) == v6_verdict::block, "retry refused");
    // An allow verdict does not slide.
    g.decide(5002, v6_verdict::allow, t0);
    check(g.lookup(5002, t0 + 1500ms) == v6_verdict::allow, "allow within ttl");
    check(g.lookup(5002, t0 + 2500ms) == v6_verdict::none, "allow expires at a fixed ttl");
    g.decide(5000, v6_verdict::allow, t0);
    check(g.lookup(5000, t0) == v6_verdict::allow, "verdict replaced");
    check(g.clear(5000).empty(), "clear returns nothing parked");
    check(g.lookup(5000, t0) == v6_verdict::none, "close forgets the port");
}

void parked_syns_follow_the_verdict() {
    ipv6_tcp_gate<int, fake_clock> g(2s);
    const tp t0{};
    int a = 1, b = 2;
    check(g.park(6000, a, t0) == udp_park_result::parked, "first syn parked");
    check(g.park(6000, b, t0) == udp_park_result::parked, "second syn parked");
    check(g.parked() == 2, "two parked");
    const auto out = g.decide(6000, v6_verdict::block, t0);
    check(out.size() == 2 && out[0] == 1 && out[1] == 2, "decide releases in order");
    check(g.parked() == 0, "none left");
    int c = 3;
    check(g.park(6000, c, t0) == udp_park_result::decided, "decided port does not park");
}

void watchdog_releases_undecided() {
    ipv6_tcp_gate<int, fake_clock> g(2s);
    const tp t0{};
    int a = 7;
    g.park(7000, a, t0);
    check(g.expire(t0 + 10ms, 20ms).empty(), "not yet due");
    const auto due = g.expire(t0 + 25ms, 20ms);
    check(due.size() == 1 && due[0].first == 7000 && due[0].second.size() == 1, "due after deadline");
}

void park_limits() {
    ipv6_tcp_gate<int, fake_clock> g(2s, UdpParkingLimits{2, 1});
    const tp t0{};
    int a = 1, b = 2, c = 3;
    check(g.park(1, a, t0) == udp_park_result::parked, "a parked");
    check(g.park(1, b, t0) == udp_park_result::full, "per-port limit");
    check(g.park(2, b, t0) == udp_park_result::parked, "b parked");
    check(g.park(3, c, t0) == udp_park_result::full, "total limit");
}

std::array<uint8_t, 16> v6(std::initializer_list<uint8_t> head, uint8_t last) {
    std::array<uint8_t, 16> a{};
    std::size_t i = 0;
    for (auto b : head) a[i++] = b;
    a[15] = last;
    return a;
}

void local_scope() {
    check(is_local_scope_ipv6(v6({0xfe, 0x80}, 1).data()), "fe80::1 link-local");
    check(is_local_scope_ipv6(v6({0xfe, 0xbf}, 1).data()), "febf:: link-local");
    check(!is_local_scope_ipv6(v6({0xfe, 0xc0}, 1).data()), "fec0:: not link-local");
    check(is_local_scope_ipv6(v6({0xfd, 0x12}, 1).data()), "fd12:: unique local");
    check(is_local_scope_ipv6(v6({0xfc}, 1).data()), "fc00:: unique local");
    check(is_local_scope_ipv6(v6({0xff, 0x02}, 1).data()), "ff02::1 multicast");
    check(is_local_scope_ipv6(v6({}, 1).data()), "::1");
    check(is_local_scope_ipv6(v6({}, 0).data()), "::");
    check(!is_local_scope_ipv6(v6({}, 2).data()), "::2 is not");
    check(!is_local_scope_ipv6(v6({0x20, 0x01, 0x0d, 0xb8}, 1).data()), "2001:db8::1 global");
    check(!is_local_scope_ipv6(v6({0x26, 0x06, 0x47, 0x00}, 1).data()), "2606:4700:: global");
}

void socket_words_to_bytes() {
    // 2001:db8:1:2:3:4:5:6 as WinDivert reports it: host-order words,
    // least significant first.
    const uint32_t w[4] = {0x00050006u, 0x00030004u, 0x00010002u, 0x20010db8u};
    const auto b = ipv6_bytes_from_socket(w);
    const uint8_t want[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02,
                              0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06};
    check(std::memcmp(b.data(), want, 16) == 0, "socket words -> network bytes");
    // IPv4-mapped stays recognisable.
    const uint32_t mapped[4] = {0x01010101u, 0x0000FFFFu, 0, 0};
    check(is_ipv4_mapped(mapped), "mapped");
    check(!is_unmanaged_ipv6(true, mapped), "mapped is managed");
    check(is_unmanaged_ipv6(true, w), "real IPv6 unmanaged");
}

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

void rst_answers_the_syn() {
    uint8_t syn[60] = {};
    syn[0] = 0x60; syn[5] = 20; syn[6] = 6; syn[7] = 128;
    const auto src = v6({0x20, 0x01, 0x0d, 0xb8, 0, 1}, 0x10);
    const auto dst = v6({0x20, 0x01, 0x0d, 0xb8, 0, 1}, 0x01);
    std::memcpy(syn + 8, src.data(), 16);
    std::memcpy(syn + 24, dst.data(), 16);
    uint8_t* t = syn + 40;
    t[0] = 0xC3; t[1] = 0x50;            // src port 50000
    t[2] = 0x01; t[3] = 0xBB;            // dst port 443
    t[4] = 0x12; t[5] = 0x34; t[6] = 0x56; t[7] = 0x78;
    t[12] = 0x50; t[13] = 0x02;          // SYN

    uint8_t rst[IPV6_RST_LEN];
    check(build_ipv6_tcp_rst(syn, sizeof(syn), rst) == IPV6_RST_LEN, "rst built");
    check((rst[0] >> 4) == 6 && be16(rst + 4) == 20 && rst[6] == 6, "ipv6 header");
    check(std::memcmp(rst + 8, dst.data(), 16) == 0, "rst source = syn destination");
    check(std::memcmp(rst + 24, src.data(), 16) == 0, "rst destination = application");
    const uint8_t* r = rst + 40;
    check(be16(r) == 443 && be16(r + 2) == 50000, "ports swapped");
    check(be32(r + 4) == 0 && be32(r + 8) == 0x12345679u, "seq 0, ack = isn + 1");
    check(r[13] == 0x14, "RST|ACK");
    // A correct checksum sums (with the pseudo header) to 0xffff -> 0.
    check(ipv6_tcp_checksum(rst, TCP_HDR_LEN) == 0, "checksum verifies");

    uint8_t synack[60];
    std::memcpy(synack, syn, sizeof(syn));
    synack[53] = 0x12;
    check(build_ipv6_tcp_rst(synack, sizeof(synack), rst) == 0, "syn+ack refused");
    uint8_t ext[60];
    std::memcpy(ext, syn, sizeof(syn));
    ext[6] = 0;                          // hop-by-hop extension header
    check(build_ipv6_tcp_rst(ext, sizeof(ext), rst) == 0, "extension header refused");
    check(build_ipv6_tcp_rst(syn, 50, rst) == 0, "short packet refused");
}

void flow_table_lifecycle() {
    ipv6_flow_table<fake_clock> t(10s);
    const tp t0{};
    check(!t.maybe_ours(7000) && !t.find(7000, t0) && !t.take(7000), "empty port");

    v6_flow f;
    f.remote[0] = 0x20; f.remote[15] = 1;
    f.remote_port = 443;
    f.group_id = 3;
    const auto id1 = t.publish(7000, f);
    check(t.maybe_ours(7000), "published port is ours");
    auto got = t.take(7000);
    check(got && got->id == id1 && got->group_id == 3 && got->remote_port == 443 && !got->has_route,
          "relay takes the published flow");

    uint8_t local[16]{};
    local[0] = 0x20; local[15] = 0x10;
    t.remember_route(7000, local, 14, 2);
    got = t.find(7000, t0);
    check(got && got->has_route && got->if_idx == 14 && got->sub_if_idx == 2 && got->local[15] == 0x10,
          "route remembered");

    // A newer CONNECT on the port replaces the flow; the old relay's retire
    // must not touch it.
    const auto id2 = t.publish(7000, f);
    check(id2 != id1, "new flow id");
    t.retire(7000, id1, t0);
    check(t.take(7000).has_value(), "stale retire ignored");

    t.retire(7000, id2, t0);
    check(!t.take(7000), "draining flow is not taken by a relay");
    check(t.find(7000, t0 + 9s).has_value(), "draining flow still translates");
    check(!t.find(7000, t0 + 10s) && !t.maybe_ours(7000), "drained flow removed");

    t.publish(7001, f);
    t.erase(7001);
    check(!t.maybe_ours(7001) && !t.find(7001, t0), "erase forgets the port");
    check(t.size() == 0, "table empty");
}

void proxy_verdict_slides() {
    ipv6_tcp_gate<int, fake_clock> g(2s);
    const tp t0{};
    g.decide(8000, v6_verdict::proxy, t0);
    check(g.lookup(8000, t0 + 1500ms) == v6_verdict::proxy, "proxy within ttl");
    check(g.lookup(8000, t0 + 3s) == v6_verdict::proxy, "SYN retransmit slides the proxy verdict");
}

}  // namespace

int main() {
    flow_table_lifecycle();
    proxy_verdict_slides();
    verdicts_cover_syns_until_ttl_or_close();
    parked_syns_follow_the_verdict();
    watchdog_releases_undecided();
    park_limits();
    local_scope();
    socket_words_to_bytes();
    rst_answers_the_syn();
    if (failures) {
        std::cerr << "ipv6_gate_tests: " << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "ipv6_gate_tests: all passed\n";
    return 0;
}
