#include "services/connection_service.hpp"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "core/decision_log.hpp"
#include "domain/process_tree_manager.hpp"
#include "process/flat_tree.hpp"
#include "process/tcp_table.hpp"
#include "process/udp_table.hpp"
#include "projection/connection_rows.hpp"
#include "rules/rule_engine_v3.hpp"
#include "rules/traffic_filter.hpp"
#include "udp/udp_port_tracker.hpp"
#include "udp/udp_session_table.hpp"

namespace clew {

// ROADMAP v0.14 #3: the strand only copies per-row facts (connection_facts);
// table reads, session / decision lookups and all JSON building happen on
// the calling (HTTP) thread. See projection/connection_rows.hpp.

namespace {

bool tcp_listening(const tcp_connection& conn) {
    return conn.state == "LISTEN" || (conn.remote_ip == "0.0.0.0" && conn.remote_port == 0);
}

// Rows the list shows. Unfiltered listings skip listening TCP sockets and
// UDP port 0 (noise in the all-process feed); a PID filter keeps them, as
// the per-process view always has.
bool tcp_shown(const tcp_connection& conn, DWORD filter_pid) {
    if (filter_pid == NO_PID_FILTER) return !tcp_listening(conn);
    return conn.pid == filter_pid;
}

bool udp_shown(const udp_endpoint& ep, DWORD filter_pid) {
    if (filter_pid == NO_PID_FILTER) return ep.local_port != 0;
    return ep.pid == filter_pid;
}

// Off-strand: OS row -> connection_row, with its decision record.
connection_row tcp_row(const tcp_connection& conn, const DecisionLog* decisions) {
    connection_row r;
    r.pid         = conn.pid;
    r.local_ip    = conn.local_ip;
    r.local_port  = conn.local_port;
    r.remote_ip   = conn.remote_ip;
    r.remote_port = conn.remote_port;
    r.remote_addr = CidrRange::ip_to_uint(conn.remote_ip);
    r.state       = conn.state;
    r.listening   = tcp_listening(conn);
    if (decisions && !r.listening) {
        r.record = decisions->find_tcp_v4(r.local_port, r.remote_addr, r.remote_port);
        if (r.record && !decision_record_fits(*r.record, r.pid)) r.record.reset();
    }
    return r;
}

// Off-strand. The destination comes from UdpSessionTable, which the NETWORK
// layer updates per packet. A UDP socket can sendto() many destinations, so
// this reports the one actually in use rather than a connect()-time address,
// and it also covers unconnected sockets. Empty until the port sends proxied
// traffic. UdpPortTracker reads are atomic, UdpSessionTable takes its own
// shared lock: neither needs the strand.
connection_row udp_row(const udp_endpoint& ep, const UdpPortTracker* tracker,
                       const UdpSessionTable* sessions, const DecisionLog* decisions) {
    connection_row r;
    r.pid        = ep.pid;
    r.local_ip   = ep.local_ip;
    r.local_port = ep.local_port;
    r.state      = "BOUND";
    if (sessions && tracker && tracker->is_active(ep.local_port)) {
        if (auto session = sessions->lookup(ep.local_port)) {
            struct in_addr addr;
            addr.s_addr = session->orig_dst_addr;  // already network byte order
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            r.remote_ip   = buf;
            r.remote_port = ntohs(session->orig_dst_port);
            r.remote_addr = CidrRange::ip_to_uint(r.remote_ip);
        }
    }
    // UDP decisions are per local port (BIND / first CONNECT); per-packet
    // destination excludes are applied by the NETWORK workers on top.
    if (decisions && ep.local_port != 0) {
        r.record = decisions->latest(decision_proto::udp, ep.local_port);
        if (r.record && !decision_record_fits(*r.record, r.pid)) r.record.reset();
    }
    return r;
}

struct facts_snapshot {
    std::vector<connection_facts> tcp;
    std::vector<connection_facts> udp;
    uint64_t                      config_version{0};
};

// ON the strand: the per-row facts that need the tree or the rule engine.
// No JSON, no formatting; one tree lookup per row, a rule-id lookup per
// distinct policy id, and the current-rules verdict only for rows without a
// record whose process is proxied now (the same strand-consistent tree /
// rules the data path uses).
class fact_collector {
public:
    explicit fact_collector(const domain::process_tree_manager& m)
        : tree_(m.tree()), rules_(m.rules()) {}

    std::vector<connection_facts> collect(const std::vector<connection_row>& rows, bool is_udp) {
        std::vector<connection_facts> out(rows.size());
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const auto& row = rows[i];
            auto& f = out[i];
            const uint32_t idx = tree_.find_by_pid(row.pid);
            f.pid_alive = idx != INVALID_IDX;
            if (f.pid_alive) {
                const auto& entry = tree_.at(idx);
                f.hijacked = entry.is_proxied();
                f.process_name = entry.name_u8;
                if (f.hijacked) f.conflict = conflict(entry);
            }
            if (row.record) {
                f.rule_id = rule_id(row.record->policy_id);
            } else if (needs_fallback(row, f.hijacked)) {
                fallback(f, row, is_udp);
                const auto origin = rules_.origin_of(tree_.at(idx));
                f.current_source  = origin.source;
                f.current_rule_id = rule_id(origin.policy_id);
            }
        }
        return out;
    }

    // Engine routing configuration version, read in the same strand hop.
    uint64_t config_version() const { return rules_.config_version(); }

private:
    // v0.14 #4: one rule scan (a matched_pids lookup per rule) per distinct
    // proxied PID, shared by all of its rows; null when there is no conflict.
    std::shared_ptr<const rule_conflict> conflict(const process_entry& entry) {
        auto [it, fresh] = conflicts_.try_emplace(entry.pid);
        if (fresh) {
            auto c = rules_.conflict_of(entry);
            if (!c.empty()) it->second = std::make_shared<const rule_conflict>(std::move(c));
        }
        return it->second;
    }

    void fallback(connection_facts& f, const connection_row& row, bool is_udp) const {
        if (is_udp && row.remote_ip.empty()) {
            // No proxied destination seen yet: only the protocol gate is known.
            const bool udp_ok = rules_.should_proxy_protocol(tree_, row.pid, "udp");
            f.fallback_proxied = udp_ok;
            f.fallback_reason  = ip_exclude_reason_name(udp_ok ? IpExcludeReason::none
                                                               : IpExcludeReason::protocol);
            return;
        }
        const auto reason = rules_.route_reason(tree_, row.pid, is_udp, row.remote_addr,
                                                row.remote_port);
        f.fallback_proxied = reason == IpExcludeReason::none;
        f.fallback_reason  = ip_exclude_reason_name(reason);
    }

    const std::string& rule_id(uint32_t policy_id) {
        for (const auto& [id, name] : rule_ids_)
            if (id == policy_id) return name;
        rule_ids_.emplace_back(policy_id, rules_.rule_id_for_policy(policy_id));
        return rule_ids_.back().second;
    }

    const flat_tree&                                tree_;
    const rule_engine_v3&                           rules_;
    std::vector<std::pair<uint32_t, std::string>>   rule_ids_;
    std::unordered_map<uint32_t, std::shared_ptr<const rule_conflict>> conflicts_;
};

std::vector<connection_row> tcp_rows(const std::vector<tcp_connection>& conns, DWORD filter_pid,
                                     const DecisionLog* decisions) {
    std::vector<connection_row> rows;
    rows.reserve(conns.size());
    for (const auto& conn : conns)
        if (tcp_shown(conn, filter_pid)) rows.push_back(tcp_row(conn, decisions));
    return rows;
}

std::vector<connection_row> udp_rows(const std::vector<udp_endpoint>& eps, DWORD filter_pid,
                                     const UdpPortTracker* tracker, const UdpSessionTable* sessions,
                                     const DecisionLog* decisions) {
    std::vector<connection_row> rows;
    rows.reserve(eps.size());
    for (const auto& ep : eps)
        if (udp_shown(ep, filter_pid)) rows.push_back(udp_row(ep, tracker, sessions, decisions));
    return rows;
}

// PIDs owning at least one socket of the unfiltered listing (what the
// process tree's activity dimming needs), sorted and unique.
nlohmann::json active_pids(const std::vector<tcp_connection>& conns,
                           const std::vector<udp_endpoint>& eps) {
    std::vector<uint32_t> pids;
    pids.reserve(conns.size() + eps.size());
    for (const auto& c : conns)
        if (tcp_shown(c, NO_PID_FILTER)) pids.push_back(c.pid);
    for (const auto& e : eps)
        if (udp_shown(e, NO_PID_FILTER)) pids.push_back(e.pid);
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    return nlohmann::json(pids);
}

} // namespace

connection_service::connection_service(strand_bound_manager& exec, UdpPortTracker* udp_tracker,
                                       const UdpSessionTable* udp_sessions,
                                       const DecisionLog* decisions)
    : exec_(exec), udp_tracker_(udp_tracker), udp_sessions_(udp_sessions), decisions_(decisions) {}

// NO_PID_FILTER (= UINT_MAX) is the "no filter, return all" sentinel.
// We can't reuse 0 because PID 0 (Idle) is a real selectable process —
// collapsing nullopt and optional(0) onto 0 would make selecting Idle
// dump the whole OS connection table.
static DWORD to_filter(std::optional<std::uint32_t> pid_filter) {
    return pid_filter ? static_cast<DWORD>(*pid_filter) : NO_PID_FILTER;
}

nlohmann::json connection_service::list_tcp(std::optional<std::uint32_t> pid_filter) const {
    const DWORD filter_pid = to_filter(pid_filter);
    const auto rows = tcp_rows(tcp_table::get_connections(filter_pid), filter_pid, decisions_);
    auto facts = exec_.query([&rows](const domain::process_tree_manager& m) {
        return fact_collector(m).collect(rows, /*is_udp=*/false);
    });
    return rows_to_json(rows, facts, /*is_udp=*/false);
}

nlohmann::json connection_service::list_udp(std::optional<std::uint32_t> pid_filter) const {
    const DWORD filter_pid = to_filter(pid_filter);
    const auto rows = udp_rows(udp_table::get_endpoints(filter_pid), filter_pid,
                               udp_tracker_, udp_sessions_, decisions_);
    auto facts = exec_.query([&rows](const domain::process_tree_manager& m) {
        return fact_collector(m).collect(rows, /*is_udp=*/true);
    });
    return rows_to_json(rows, facts, /*is_udp=*/true);
}

nlohmann::json connection_service::list_all(std::optional<std::uint32_t> pid_filter) const {
    const DWORD filter_pid = to_filter(pid_filter);
    // Full tables once: the rows honour the filter, active_pids never does.
    const auto all_tcp = tcp_table::get_connections(NO_PID_FILTER);
    const auto all_udp = udp_table::get_endpoints(NO_PID_FILTER);
    const auto tcp = tcp_rows(all_tcp, filter_pid, decisions_);
    const auto udp = udp_rows(all_udp, filter_pid, udp_tracker_, udp_sessions_, decisions_);

    // One strand hop for both transports.
    auto facts = exec_.query([&tcp, &udp](const domain::process_tree_manager& m) {
        fact_collector collect(m);
        facts_snapshot s;
        s.tcp = collect.collect(tcp, /*is_udp=*/false);
        s.udp = collect.collect(udp, /*is_udp=*/true);
        s.config_version = collect.config_version();
        return s;
    });

    nlohmann::json out;
    out["tcp"]         = rows_to_json(tcp, facts.tcp, /*is_udp=*/false);
    out["udp"]         = rows_to_json(udp, facts.udp, /*is_udp=*/true);
    out["active_pids"] = active_pids(all_tcp, all_udp);
    // v0.14 #4: the routing configuration the rows' `conflict` / `estimate`
    // were computed under, from the same strand hop. A row whose recorded
    // decision.config_version is lower was decided under older rules.
    out["config_version"] = facts.config_version;
    return out;
}

} // namespace clew
