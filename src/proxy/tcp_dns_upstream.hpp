#pragma once

// Where a proxied process's TCP connection to port 53 is sent.
//
// Chromium's built-in resolver (and anything else doing DNS over TCP) talks
// to the system resolver directly. Sent through the proxy unchanged, that
// query would ask the user's local/ISP resolver from the proxy's network,
// which usually fails or returns polluted answers. The relay therefore
// rewrites the destination of proxied TCP :53 flows to the configured DNS
// upstream (`dns.upstream_host:dns.upstream_port`, default 8.8.8.8:53).
// This applies whether or not the DNS forwarder (`dns.enabled`) is on.
//
// Fallback: the relay speaks SOCKS5 with an IPv4 destination, so only an
// IPv4 literal can be used. When upstream_host is not one (a hostname, an
// IPv6 literal, or a loopback / unspecified address, which would mean the
// proxy server's own machine), 8.8.8.8:53 is used and a warning is logged
// once per config change.
//
// Published by DnsManager::apply (startup and every config change), read
// lock-free by the relay.

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace clew::tcp_dns {

inline constexpr uint32_t kFallbackIp   = 0x08080808;  // 8.8.8.8, host order
inline constexpr uint16_t kFallbackPort = 53;

struct endpoint {
    uint32_t ip;    // host byte order
    uint16_t port;
    bool     fallback;  // true when the configured upstream could not be used
};

// Strict dotted-quad parser (no leading '+', no empty parts, each 0..255).
inline std::optional<uint32_t> parse_ipv4(std::string_view s) {
    uint32_t out = 0;
    int parts = 0;
    std::size_t i = 0;
    while (parts < 4) {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return std::nullopt;
        uint32_t v = 0;
        int digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + static_cast<uint32_t>(s[i] - '0');
            if (++digits > 3 || v > 255) return std::nullopt;
            ++i;
        }
        out = (out << 8) | v;
        ++parts;
        if (parts < 4) {
            if (i >= s.size() || s[i] != '.') return std::nullopt;
            ++i;
        }
    }
    if (i != s.size()) return std::nullopt;
    return out;
}

// The endpoint TCP :53 is rewritten to for a given DNS config.
inline endpoint resolve(std::string_view upstream_host, uint16_t upstream_port) {
    const auto ip = parse_ipv4(upstream_host);
    const bool usable = ip && *ip != 0 && (*ip >> 24) != 127 && upstream_port != 0;
    if (!usable) return {kFallbackIp, kFallbackPort, true};
    return {*ip, upstream_port, false};
}

namespace detail {
// ip << 16 | port; fallback until the first publish.
inline std::atomic<uint64_t>& slot() {
    static std::atomic<uint64_t> v{(uint64_t{kFallbackIp} << 16) | kFallbackPort};
    return v;
}
} // namespace detail

inline void publish(const endpoint& ep) {
    detail::slot().store((uint64_t{ep.ip} << 16) | ep.port, std::memory_order_relaxed);
}

inline endpoint current() {
    const uint64_t v = detail::slot().load(std::memory_order_relaxed);
    return {static_cast<uint32_t>(v >> 16), static_cast<uint16_t>(v & 0xFFFF), false};
}

} // namespace clew::tcp_dns
