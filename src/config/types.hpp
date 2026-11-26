#pragma once

#include <string>
#include <format>
#include <vector>
#include <cstdint>
#include <array>
#include <cstdio>
#include <optional>
#include <string_view>
#include <unordered_set>
#include <chrono>
#include <nlohmann/json.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>


namespace clew {

// ============================================================
// CIDR Range - IP range matching
// ============================================================

struct CidrRange {
    uint32_t network = 0;   // IPv4, host byte order
    uint32_t mask = 0;
    // IPv6 range (v0.14.2): network bytes in network order, prefix 0..128.
    bool v6 = false;
    std::array<uint8_t, 16> net6{};
    uint8_t prefix6 = 0;

    static uint32_t ip_to_uint(const std::string& ip) {
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t d;
        if (sscanf_s(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
        return (a << 24) | (b << 16) | (c << 8) | d;
    }

    static std::string uint_to_ip(uint32_t ip) {
        return std::format("{}.{}.{}.{}",
                           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                           (ip >> 8)  & 0xFF,  ip        & 0xFF);
    }

    // RFC 4291 text form ("2001:db8::1", "::", "::ffff:1.2.3.4") to network
    // order bytes. No zone ids. Portable on purpose (unit tests run off Windows).
    static std::optional<std::array<uint8_t, 16>> parse_ipv6(std::string_view s) {
        std::array<uint8_t, 16> out{};
        std::array<uint16_t, 8> groups{};
        int n = 0;          // groups written
        int gap = -1;       // index where "::" sits
        size_t i = 0;
        if (s.empty()) return std::nullopt;
        if (s.starts_with("::")) { gap = 0; i = 2; if (s.size() == 2) return out; }
        else if (s[0] == ':') return std::nullopt;
        while (i < s.size()) {
            if (n >= 8) return std::nullopt;
            const size_t start = i;
            const size_t end = s.find(':', i);
            const std::string_view tok = s.substr(start, (end == std::string_view::npos ? s.size() : end) - start);
            if (tok.find('.') != std::string_view::npos) {
                // Embedded IPv4 tail: must be last, takes two groups.
                if (end != std::string_view::npos || n > 6) return std::nullopt;
                unsigned a, b, c, d; char extra;
                const std::string t(tok);
                if (std::sscanf(t.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4 ||
                    a > 255 || b > 255 || c > 255 || d > 255) return std::nullopt;
                groups[n++] = static_cast<uint16_t>((a << 8) | b);
                groups[n++] = static_cast<uint16_t>((c << 8) | d);
                i = s.size();
                break;
            }
            if (tok.empty() || tok.size() > 4) return std::nullopt;
            uint16_t v = 0;
            for (char ch : tok) {
                int h;
                if (ch >= '0' && ch <= '9') h = ch - '0';
                else if (ch >= 'a' && ch <= 'f') h = ch - 'a' + 10;
                else if (ch >= 'A' && ch <= 'F') h = ch - 'A' + 10;
                else return std::nullopt;
                v = static_cast<uint16_t>((v << 4) | h);
            }
            groups[n++] = v;
            if (end == std::string_view::npos) { i = s.size(); break; }
            i = end + 1;
            if (i < s.size() && s[i] == ':') {
                if (gap >= 0) return std::nullopt;
                gap = n; ++i;
            } else if (i == s.size()) {
                return std::nullopt;   // trailing single ':'
            }
        }
        if (gap < 0 && n != 8) return std::nullopt;
        if (gap >= 0 && n >= 8) return std::nullopt;
        std::array<uint16_t, 8> full{};
        if (gap < 0) {
            full = groups;
        } else {
            const int tail = n - gap;
            for (int k = 0; k < gap; ++k) full[k] = groups[k];
            for (int k = 0; k < tail; ++k) full[8 - tail + k] = groups[gap + k];
        }
        for (int k = 0; k < 8; ++k) {
            out[2 * k]     = static_cast<uint8_t>(full[k] >> 8);
            out[2 * k + 1] = static_cast<uint8_t>(full[k] & 0xFF);
        }
        return out;
    }

    // Shortest form: lowercase, longest run (>= 2) of zero groups as "::".
    static std::string ipv6_to_string(const uint8_t* b) {
        uint16_t g[8];
        for (int k = 0; k < 8; ++k) g[k] = static_cast<uint16_t>((b[2 * k] << 8) | b[2 * k + 1]);
        int best = -1, best_len = 0;
        for (int k = 0; k < 8;) {
            if (g[k] != 0) { ++k; continue; }
            int j = k;
            while (j < 8 && g[j] == 0) ++j;
            if (j - k > best_len) { best = k; best_len = j - k; }
            k = j;
        }
        if (best_len < 2) best = -1;
        std::string out;
        for (int k = 0; k < 8; ++k) {
            if (k == best) { out += "::"; k += best_len - 1; continue; }
            if (!out.empty() && out.back() != ':') out += ':';
            out += std::format("{:x}", g[k]);
        }
        return out;
    }

    // Parse "10.0.0.0/8", "1.2.3.4", "2001:db8::/32" or "2001:db8::1".
    static CidrRange parse(const std::string& cidr) {
        CidrRange r;
        size_t slash = cidr.find('/');
        const std::string addr = cidr.substr(0, slash);
        if (addr.find(':') != std::string::npos) {
            r.v6 = true;
            int prefix_len = 128;
            if (slash != std::string::npos) prefix_len = std::stoi(cidr.substr(slash + 1));
            if (prefix_len < 0) prefix_len = 0;
            if (prefix_len > 128) prefix_len = 128;
            r.prefix6 = static_cast<uint8_t>(prefix_len);
            const auto bytes = parse_ipv6(addr);
            if (!bytes) {
                // Unparseable: match nothing rather than "::/0".
                r.prefix6 = 128;
                r.net6.fill(0xFF);
                return r;
            }
            r.net6 = *bytes;
            for (int k = 0; k < 16; ++k) {
                const int bits = prefix_len - 8 * k;
                const uint8_t m = bits >= 8 ? 0xFF : bits <= 0 ? 0 : static_cast<uint8_t>(0xFF << (8 - bits));
                r.net6[k] &= m;
            }
            return r;
        }
        if (slash == std::string::npos) {
            r.network = ip_to_uint(cidr);
            r.mask = 0xFFFFFFFF;
        } else {
            int prefix_len = std::stoi(cidr.substr(slash + 1));
            r.mask = (prefix_len == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_len));
            r.network = ip_to_uint(cidr.substr(0, slash)) & r.mask;
        }
        return r;
    }

    // IPv4 destination (host order). An IPv6 range never matches it.
    bool matches(uint32_t ip) const {
        return !v6 && (ip & mask) == network;
    }

    bool matches(const std::string& ip) const {
        return matches(ip_to_uint(ip));
    }

    // IPv6 destination (16 bytes, network order). An IPv4 range never matches it.
    bool matches_v6(const uint8_t* ip) const {
        if (!v6) return false;
        int bits = prefix6;
        for (int k = 0; k < 16 && bits > 0; ++k, bits -= 8) {
            const uint8_t m = bits >= 8 ? 0xFF : static_cast<uint8_t>(0xFF << (8 - bits));
            if ((ip[k] & m) != net6[k]) return false;
        }
        return true;
    }

    std::string to_string() const {
        if (v6) return std::format("{}/{}", ipv6_to_string(net6.data()), prefix6);
        // Find prefix length from mask
        int prefix = 0;
        uint32_t m = mask;
        while (m & 0x80000000) { prefix++; m <<= 1; }
        return std::format("{}/{}", uint_to_ip(network), prefix);
    }
};

inline void to_json(nlohmann::json& j, const CidrRange& r) {
    j = r.to_string();
}

inline void from_json(const nlohmann::json& j, CidrRange& r) {
    r = CidrRange::parse(j.get<std::string>());
}

// ============================================================
// Port Range
// ============================================================

struct PortRange {
    uint16_t start = 0;
    uint16_t end = 0;

    // Parse "80", "80-443", "1024-65535"
    static PortRange parse(const std::string& s) {
        PortRange r;
        size_t dash = s.find('-');
        if (dash == std::string::npos) {
            r.start = r.end = static_cast<uint16_t>(std::stoi(s));
        } else {
            r.start = static_cast<uint16_t>(std::stoi(s.substr(0, dash)));
            r.end = static_cast<uint16_t>(std::stoi(s.substr(dash + 1)));
        }
        return r;
    }

    bool matches(uint16_t port) const {
        return port >= start && port <= end;
    }

    std::string to_string() const {
        if (start == end) return std::to_string(start);
        return std::format("{}-{}", start, end);
    }
};

inline void to_json(nlohmann::json& j, const PortRange& r) {
    j = r.to_string();
}

inline void from_json(const nlohmann::json& j, PortRange& r) {
    r = PortRange::parse(j.get<std::string>());
}

// ============================================================
// Proxy Target - Per-rule proxy destination
// ============================================================

struct ProxyTarget {
    std::string type = "socks5";   // "socks5" | "http"
    std::string host = "127.0.0.1";
    uint16_t port = 7890;
    std::string user;              // Optional auth
    std::string password;          // Optional auth

    bool operator==(const ProxyTarget& o) const {
        return type == o.type && host == o.host && port == o.port &&
               user == o.user && password == o.password;
    }

    std::string to_string() const {
        return std::format("{}://{}:{}", type, host, port);
    }
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ProxyTarget, type, host, port, user, password)

// ============================================================
// Proxy Group - Named proxy configuration
// ============================================================

struct ProxyGroup {
    uint32_t id = 0;                    // Auto-increment ID, 0 = default group
    std::string name = "default";       // Display name
    std::string host = "127.0.0.1";
    uint16_t port = 7890;
    std::string type = "socks5";        // Only "socks5" for now
    std::string test_url = "http://www.gstatic.com/generate_204";
    std::string user;                   // Optional RFC 1929 SOCKS5 username
    std::string password;               // Optional RFC 1929 SOCKS5 password

    std::string to_string() const {
        return std::format("{}://{}:{}", type, host, port);
    }
};

inline void to_json(nlohmann::json& j, const ProxyGroup& g) {
    j = nlohmann::json{
        {"id",       g.id},
        {"name",     g.name},
        {"host",     g.host},
        {"port",     g.port},
        {"type",     g.type},
        {"test_url", g.test_url},
    };
    if (!g.user.empty())     j["user"]     = g.user;
    if (!g.password.empty()) j["password"] = g.password;
}

inline void from_json(const nlohmann::json& j, ProxyGroup& g) {
    ProxyGroup def;
    g.id       = j.value("id", def.id);
    g.name     = j.value("name", def.name);
    g.host     = j.value("host", def.host);
    g.port     = j.value("port", def.port);
    g.type     = j.value("type", def.type);
    g.test_url = j.value("test_url", def.test_url);
    g.user     = j.contains("user") && j["user"].is_string() ? j["user"].get<std::string>() : std::string{};
    g.password = j.contains("password") && j["password"].is_string() ? j["password"].get<std::string>() : std::string{};
}

// ============================================================
// Traffic Filter - IP/port include/exclude
// ============================================================

struct TrafficFilter {
    std::vector<CidrRange> include_cidrs;   // If non-empty, only proxy matching
    std::vector<CidrRange> exclude_cidrs;   // Always exclude matching
    std::vector<PortRange> include_ports;   // If non-empty, only proxy matching
    std::vector<PortRange> exclude_ports;   // Always exclude matching
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(TrafficFilter, include_cidrs, exclude_cidrs, include_ports, exclude_ports)

// ============================================================
// Process identity key: (pid, psn)
// ============================================================

struct ProcessKey {
    DWORD pid = 0;
    uint64_t psn = 0;

    bool operator==(const ProcessKey&) const = default;
};

struct ProcessKeyHash {
    size_t operator()(const ProcessKey& k) const noexcept {
        uint64_t h = k.psn ^ (static_cast<uint64_t>(k.pid) * 0x9E3779B97F4A7C15ULL);
        h ^= h >> 30;
        h *= 0xBF58476D1CE4E5B9ULL;
        h ^= h >> 27;
        h *= 0x94D049BB133111EBULL;
        h ^= h >> 31;
        return static_cast<size_t>(h);
    }
};

// ============================================================
// Child-process-tree exclusion (v0.15 #1)
// ============================================================
//
// A descendant matching any entry (plus its entire subtree) does not inherit
// the parent rule and goes direct with decision_reason::rule_exclude_child.
// Empty entries never match.
struct ChildExclusion {
    std::string process_name;       // Wildcard pattern (e.g. "ssh.exe", "scp*")
    std::string cmdline_pattern;    // Keyword or wildcard pattern (optional)
    std::string image_path_pattern; // Directory prefix match (optional)

    bool empty() const {
        return process_name.empty() && cmdline_pattern.empty() && image_path_pattern.empty();
    }

    bool operator==(const ChildExclusion&) const = default;
};

inline void to_json(nlohmann::json& j, const ChildExclusion& c) {
    j = nlohmann::json{
        {"process_name", c.process_name},
        {"cmdline_pattern", c.cmdline_pattern},
        {"image_path_pattern", c.image_path_pattern}
    };
}

inline void from_json(const nlohmann::json& j, ChildExclusion& c) {
    if (j.is_string()) {
        c.process_name = j.get<std::string>();
        c.cmdline_pattern.clear();
        c.image_path_pattern.clear();
        return;
    }
    c.process_name = j.value("process_name", std::string(""));
    c.cmdline_pattern = j.value("cmdline_pattern", std::string(""));
    c.image_path_pattern = j.value("image_path_pattern", std::string(""));
}

// ============================================================
// Auto Rule
// ============================================================

struct AutoRule {
    AutoRule() = default;
    AutoRule(const AutoRule&) = default;
    AutoRule& operator=(const AutoRule&) = default;
    AutoRule(AutoRule&&) noexcept = default;
    AutoRule& operator=(AutoRule&&) noexcept = default;

    std::string id;
    std::string name;
    bool enabled = true;
    std::string process_name;        // Wildcard pattern (e.g. "curl*")
    std::string cmdline_pattern;     // Wildcard pattern (optional)
    std::string image_path_pattern;  // Directory prefix or wildcard match (e.g. "C:\\Python311\\")
    std::string package_family_name; // Store/MSIX PackageFamilyName pattern (e.g. "Microsoft.WindowsTerminal_8wekyb3d8bbwe")
    bool hack_tree = false;
    TrafficFilter dst_filter;
    std::vector<ChildExclusion> child_exclusions; // Subtrees under this rule that go direct
    uint32_t proxy_group_id = 0;    // References ProxyGroup, 0 = default group
    std::string protocol = "tcp";   // "tcp", "udp", or "both"
    ProxyTarget proxy;              // Legacy: kept for backward compat during migration

    // Runtime helpers
    bool matches_tcp() const { return protocol == "tcp" || protocol == "both"; }
    bool matches_udp() const { return protocol == "udp" || protocol == "both"; }
    bool matches_process(DWORD pid, uint64_t psn) const {
        return matched_processes.contains(ProcessKey{pid, psn});
    }
    bool is_child_excluded(DWORD pid, uint64_t psn) const {
        return child_excluded_processes.contains(ProcessKey{pid, psn});
    }

    // Runtime state (not serialized), keyed by (pid, psn) so a recycled PID
    // never inherits or shadows a dead predecessor's match state. Per-process
    // exclusions remain engine-owned in rule_engine_v3::exclusions_.
    std::unordered_set<ProcessKey, ProcessKeyHash> matched_processes;
    std::unordered_set<ProcessKey, ProcessKeyHash> child_excluded_processes;
};

inline void to_json(nlohmann::json& j, const AutoRule& r) {
    j = nlohmann::json{
        {"id", r.id},
        {"name", r.name},
        {"enabled", r.enabled},
        {"process_name", r.process_name},
        {"cmdline_pattern", r.cmdline_pattern},
        {"image_path_pattern", r.image_path_pattern},
        {"hack_tree", r.hack_tree},
        {"dst_filter", r.dst_filter},
        {"child_exclusions", r.child_exclusions},
        {"proxy_group_id", r.proxy_group_id},
        {"protocol", r.protocol},
        {"proxy", r.proxy}
    };
    if (!r.package_family_name.empty()) {
        j["package_family_name"] = r.package_family_name;
    }
}

inline void from_json(const nlohmann::json& j, AutoRule& r) {
    r.id = j.value("id", std::string(""));
    r.name = j.value("name", "");
    r.enabled = j.value("enabled", true);
    r.process_name = j.value("process_name", "");
    r.cmdline_pattern = j.value("cmdline_pattern", "");
    r.image_path_pattern = j.value("image_path_pattern", "");
    r.package_family_name = j.value("package_family_name", "");
    r.hack_tree = j.value("hack_tree", true);
    if (j.contains("dst_filter")) j.at("dst_filter").get_to(r.dst_filter);
    if (j.contains("child_exclusions") && j.at("child_exclusions").is_array()) {
        j.at("child_exclusions").get_to(r.child_exclusions);
    } else {
        r.child_exclusions.clear();
    }
    r.proxy_group_id = j.value("proxy_group_id", 0u);
    r.protocol = j.value("protocol", std::string("tcp"));
    if (j.contains("proxy")) j.at("proxy").get_to(r.proxy);
    // Runtime state not deserialized
}

// ============================================================
// UI Config
// ============================================================

struct UiConfig {
    int window_width = 1200;
    int window_height = 800;
    int window_x = -1;      // -1 = center
    int window_y = -1;
    bool dark_mode = true;
    bool close_to_tray = true;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(UiConfig, window_width, window_height, window_x, window_y, dark_mode, close_to_tray)

// ============================================================
// Config V2 - Top-level configuration
// ============================================================

struct DnsConfig {
    bool enabled = false;                       // Master DNS proxy switch
    std::string mode = "forwarder";             // "forwarder" (future: "hook")
    std::string upstream_host = "8.8.8.8";      // Upstream DNS server
    uint16_t upstream_port = 53;                // Upstream DNS port (fixed to 53 for now)
    std::string listen_host = "127.0.0.2";      // Local listen address (forwarder mode)
    uint16_t listen_port = 53;                  // Local listen port (forwarder mode)
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(DnsConfig, enabled, mode, upstream_host, upstream_port, listen_host, listen_port)

// TCP SYN parking: hold a connection's first SYN until the SOCKET layer has
// decided whether to proxy it, instead of letting fresh processes' first
// connection escape. Read at startup only (the pool and injector thread are
// allocated then); changing it requires a restart.
//   enabled      kill switch. false = pre-v0.10 behavior (no pool, no injector,
//                no synchronous PID resolve, two-state tracker), for when the
//                new code itself misbehaves. Short-lived processes escape
//                interception again in that mode.
//   watchdog_ms  how long a SYN may wait for its decision before it is
//                released direct (clamped 5..50; normal waits are < 1ms).
//   pool_size    parked SYNs held at once (clamped 32..4096; peak seen 17
//                under a 300-connection burst).
struct TcpSynParkingConfig {
    bool enabled = true;
    int  watchdog_ms = 20;
    int  pool_size = 256;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(TcpSynParkingConfig, enabled, watchdog_ms, pool_size)

// UDP first-packet parking: datagrams from a port whose BIND decision has not
// been published yet wait for it instead of leaving direct. Startup only.
//   enabled      kill switch. false = pre-v0.11 behavior (a datagram sent in
//                the first ~1 ms of a socket's life can leave direct).
//   watchdog_ms  longest wait before a datagram is sent direct and its port
//                pinned direct (clamped 5..50). Sockets opened before
//                ProxyClaw started pay this once per port.
struct UdpFirstPacketConfig {
    bool enabled = true;
    int  watchdog_ms = 20;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(UdpFirstPacketConfig, enabled, watchdog_ms)

// IPv6 handling for proxied processes.
//   mode  "block" (default): a proxied process's IPv6 TCP connect is refused
//         (RST) and its IPv6 UDP datagrams are dropped, so it falls back to
//         IPv4 and goes through the proxy. Local-scope IPv6 and destinations
//         its rule excludes are not blocked.
//         "direct": IPv6 leaves direct, past the proxy (pre-v0.14.1).
//         "proxy": IPv6 TCP and UDP go through the SOCKS5 proxy (ATYP 4);
//         opt-in, since the proxy must reach IPv6 and relay IPv6 UDP.
//         Read at runtime; any other value means block.
struct Ipv6Config {
    std::string mode = "block";
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Ipv6Config, mode)

// mode: "block" (default) refuse IPv6 of proxied processes so they fall back
// to IPv4; "proxy" send their IPv6 TCP and UDP through SOCKS5 (ATYP 4);
// "direct" leave IPv6 alone.
inline bool ipv6_blocks(const Ipv6Config& c) noexcept { return c.mode != "direct"; }
inline bool ipv6_proxies(const Ipv6Config& c) noexcept { return c.mode == "proxy"; }

// How proxied processes are intercepted. Startup only (restart to switch).
//   mode  "windivert" (default): the WinDivert driver redirects packets.
//         "hook": proxyclaw_hook64.dll is injected into proxied processes
//         and redirects their TCP connects in user mode (no driver; see
//         hook/hook_mode.hpp for what it does not cover). Any other value
//         means windivert.
struct InterceptionConfig {
    std::string mode = "windivert";
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(InterceptionConfig, mode)

inline bool uses_hook(const InterceptionConfig& c) noexcept { return c.mode == "hook"; }

struct ConfigV2 {
    int version = 2;
    ProxyTarget default_proxy;
    std::vector<ProxyGroup> proxy_groups;       // NEW: named proxy configurations
    uint32_t next_group_id = 1;                 // NEW: auto-increment counter (0 = default, starts at 1)
    std::vector<std::string> default_exclude_cidrs = {
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16"
    };
    std::vector<AutoRule> auto_rules;
    UiConfig ui;
    int io_threads = 0;                         // NEW: 0 = hardware_concurrency()/2
    std::string log_level = "info";             // Runtime log level: debug/info/warning/error
    DnsConfig dns;                              // NEW: DNS proxy configuration
    TcpSynParkingConfig tcp_syn_parking;        // SYN parking switch + tuning (startup only)
    UdpFirstPacketConfig udp_first_packet;      // UDP first-packet parking (startup only)
    Ipv6Config ipv6;                            // IPv6 block / proxy / direct (runtime)
    InterceptionConfig interception;            // windivert / hook (startup only)
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ConfigV2, version, default_proxy, proxy_groups, next_group_id, default_exclude_cidrs, auto_rules, ui, io_threads, log_level, dns, tcp_syn_parking, udp_first_packet, ipv6, interception)

} // namespace clew
