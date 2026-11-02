// UDP per-packet addressing primitives (src/udp/udp_flow.hpp) and the SOCKS5
// UDP codec round trip that carries each datagram's own destination.
// No driver, no admin rights.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "udp/socks5_udp_codec.hpp"
#include "udp/udp_flow.hpp"

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

uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    // network byte order, as read from an IP header
    uint32_t v{};
    auto* p = reinterpret_cast<uint8_t*>(&v);
    p[0] = a; p[1] = b; p[2] = c; p[3] = d;
    return v;
}

void peers_track_address_and_port() {
    UdpPeerSet peers;
    peers.add(ip(1, 1, 1, 1), 53);
    peers.add(ip(8, 8, 8, 8), 53);
    check(peers.contains(ip(1, 1, 1, 1), 53), "first peer kept");
    check(peers.contains(ip(8, 8, 8, 8), 53), "second peer kept (no overwrite)");
    check(!peers.contains(ip(1, 1, 1, 1), 54), "same address, other port is not a peer");
    check(!peers.contains(ip(9, 9, 9, 9), 53), "unknown address is not a peer");
    peers.add(ip(1, 1, 1, 1), 53);
    check(peers.size() == 2, "re-adding a peer does not grow the set");
}

void peers_evict_least_recently_used() {
    UdpPeerSet peers(2);
    auto t0 = UdpPeerSet::clock::now();
    check(!peers.add(ip(10, 0, 0, 1), 1, t0), "no eviction below capacity");
    check(!peers.add(ip(10, 0, 0, 2), 2, t0 + 1s), "no eviction at capacity");
    peers.add(ip(10, 0, 0, 1), 1, t0 + 2s);  // refresh the first
    check(peers.add(ip(10, 0, 0, 3), 3, t0 + 3s), "eviction reported when full");
    check(peers.contains(ip(10, 0, 0, 1), 1), "recently used peer survives");
    check(!peers.contains(ip(10, 0, 0, 2), 2), "least recently used peer evicted");
    check(peers.contains(ip(10, 0, 0, 3), 3), "new peer added");
}

void codec_keeps_each_destination() {
    const std::vector<uint8_t> payload{0xde, 0xad, 0xbe, 0xef};
    struct Case { uint32_t addr; uint16_t port; };
    for (auto c : {Case{ip(1, 1, 1, 1), 53}, Case{ip(8, 8, 4, 4), 443}, Case{ip(203, 0, 113, 9), 65535}}) {
        auto frame = socks5_udp::encode(c.addr, c.port, payload.data(), payload.size());
        auto decoded = socks5_udp::decode(frame.data(), frame.size());
        check(decoded.has_value(), "frame decodes");
        if (!decoded) continue;
        check(decoded->addr_net == c.addr, "address round trips");
        check(decoded->port_host == c.port, "port round trips");
        check(decoded->data_len == payload.size() &&
              std::equal(payload.begin(), payload.end(), decoded->data), "payload round trips");
    }
    std::vector<uint8_t> fragmented{0, 0, 1, 1, 1, 1, 1, 1, 0, 53, 0xaa};
    check(!socks5_udp::decode(fragmented.data(), fragmented.size()), "fragmented frame rejected");
}

void queue_limits_are_sane() {
    UdpQueueLimits l;
    check(l.max_port_packets > 0 && l.max_port_packets < l.max_total_packets, "per-port limit below total");
    check(l.max_total_bytes >= 65535 * 64, "byte limit fits at least 64 max-size datagrams");
}

} // namespace

int main() {
    peers_track_address_and_port();
    peers_evict_least_recently_used();
    codec_keeps_each_destination();
    queue_limits_are_sane();
    if (failures) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "udp_flow_tests: all passed\n";
    return 0;
}
