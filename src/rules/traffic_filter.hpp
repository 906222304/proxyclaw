#pragma once

#include <cstdint>
#include <vector>
#include "config/types.hpp"

namespace clew {

// Why a destination goes DIRECT instead of through the proxy. `none` means
// "proxy it". The same answer drives the TCP SOCKET layer, the UDP SOCKET and
// NETWORK layers and the connection list in the UI, so what the UI shows is
// what the data path actually did.
enum class IpExcludeReason {
    none,
    global,             // config.default_exclude_cidrs
    rule,               // rule.dst_filter.exclude_cidrs
    rule_port,          // rule.dst_filter.exclude_ports
    include_cidr_miss,  // rule.dst_filter.include_cidrs set, no match
    include_port_miss,  // rule.dst_filter.include_ports set, no match
    protocol,           // rule.protocol does not cover this transport
};

inline const char* ip_exclude_reason_name(IpExcludeReason reason) noexcept {
    switch (reason) {
    case IpExcludeReason::global:            return "global_exclude";
    case IpExcludeReason::rule:              return "rule_exclude";
    case IpExcludeReason::rule_port:         return "rule_exclude_port";
    case IpExcludeReason::include_cidr_miss: return "rule_include_cidr_miss";
    case IpExcludeReason::include_port_miss: return "rule_include_port_miss";
    case IpExcludeReason::protocol:          return "rule_protocol";
    default:                                 return "none";
    }
}

// The one destination check. Order:
//   1. global exclude CIDRs
//   2. rule exclude CIDRs, then rule exclude ports
//   3. rule include CIDRs (if any, must match)
//   4. rule include ports (if any, must match)
// `rule` is null for manual hijacks: only the global excludes apply.
[[nodiscard]] inline IpExcludeReason evaluate_destination(
        const std::vector<CidrRange>& global_cidrs,
        const TrafficFilter* rule,
        uint32_t dest_ip,
        uint16_t dest_port) noexcept {
    for (const auto& cidr : global_cidrs) {
        if (cidr.matches(dest_ip)) return IpExcludeReason::global;
    }
    if (!rule) return IpExcludeReason::none;

    for (const auto& cidr : rule->exclude_cidrs) {
        if (cidr.matches(dest_ip)) return IpExcludeReason::rule;
    }
    for (const auto& pr : rule->exclude_ports) {
        if (pr.matches(dest_port)) return IpExcludeReason::rule_port;
    }
    if (!rule->include_cidrs.empty()) {
        bool hit = false;
        for (const auto& cidr : rule->include_cidrs) {
            if (cidr.matches(dest_ip)) { hit = true; break; }
        }
        if (!hit) return IpExcludeReason::include_cidr_miss;
    }
    if (!rule->include_ports.empty()) {
        bool hit = false;
        for (const auto& pr : rule->include_ports) {
            if (pr.matches(dest_port)) { hit = true; break; }
        }
        if (!hit) return IpExcludeReason::include_port_miss;
    }
    return IpExcludeReason::none;
}

// The same check for an IPv6 destination, used only to decide whether a
// proxied process's IPv6 flow is blocked (ProxyClaw does not proxy IPv6).
// The CIDR lists hold IPv4 ranges only: an exclude CIDR never matches, and a
// rule that names include CIDRs never covers an IPv6 destination. Local-scope
// IPv6 (link-local, unique local, multicast) counts as a global exclude, the
// counterpart of the default private IPv4 excludes.
[[nodiscard]] inline IpExcludeReason evaluate_destination_v6(
        bool local_scope,
        const TrafficFilter* rule,
        uint16_t dest_port) noexcept {
    if (local_scope) return IpExcludeReason::global;
    if (!rule) return IpExcludeReason::none;
    for (const auto& pr : rule->exclude_ports) {
        if (pr.matches(dest_port)) return IpExcludeReason::rule_port;
    }
    if (!rule->include_cidrs.empty()) return IpExcludeReason::include_cidr_miss;
    if (!rule->include_ports.empty()) {
        bool hit = false;
        for (const auto& pr : rule->include_ports) {
            if (pr.matches(dest_port)) { hit = true; break; }
        }
        if (!hit) return IpExcludeReason::include_port_miss;
    }
    return IpExcludeReason::none;
}

// Immutable-by-convention snapshot of one rule's destination policy, used by
// the NETWORK workers through PolicyTable. An empty `rule` filter adds nothing
// to the global excludes (manual hijacks, unmatched pids, removed rules).
struct IpExcludePolicy {
    std::vector<CidrRange> global_cidrs;
    TrafficFilter rule;

    [[nodiscard]] IpExcludeReason evaluate(uint32_t dest_ip, uint16_t dest_port) const noexcept {
        return evaluate_destination(global_cidrs, &rule, dest_ip, dest_port);
    }

    [[nodiscard]] IpExcludeReason evaluate_v6(bool local_scope, uint16_t dest_port) const noexcept {
        return evaluate_destination_v6(local_scope, &rule, dest_port);
    }
};

// ============================================================
// Traffic Filter Engine
// Rule-only check (no global excludes), kept for callers that hold a bare
// TrafficFilter. The data path uses rule_engine_v3::destination_reason().
// ============================================================

class TrafficFilterEngine {
public:
    // Returns true if the connection should be proxied.
    // Evaluation order:
    //   1. Loopback (127.0.0.0/8) → always DIRECT (never proxy)
    //   2. Exclude CIDRs → DIRECT
    //   3. Exclude Ports → DIRECT
    //   4. Include CIDRs (if non-empty, must match) → proxy or DIRECT
    //   5. Include Ports (if non-empty, must match) → proxy or DIRECT
    //   6. Default: proxy
    static bool should_proxy(uint32_t dest_ip, uint16_t dest_port, const TrafficFilter& filter) {
        // Always skip loopback
        if ((dest_ip >> 24) == 127) return false;

        static const std::vector<CidrRange> no_global;
        return evaluate_destination(no_global, &filter, dest_ip, dest_port)
            == IpExcludeReason::none;
    }

    // Convenience overload with string IP
    static bool should_proxy(const std::string& dest_ip, uint16_t dest_port, const TrafficFilter& filter) {
        return should_proxy(CidrRange::ip_to_uint(dest_ip), dest_port, filter);
    }
};

} // namespace clew
