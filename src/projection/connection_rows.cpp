#include "projection/connection_rows.hpp"

#include <format>
#include <utility>

namespace clew {

namespace {

// Rows without a decision record: the verdict the data path would reach
// under the CURRENT rules, as computed on the strand.
void set_fallback(nlohmann::json& c, const connection_facts& f) {
    c["proxy_status"] = f.fallback_proxied ? "PROXIED" : "IGNORED";
    c["route_reason"] = f.fallback_reason ? f.fallback_reason : "none";
}

void mark_recomputed(nlohmann::json& c) {
    c["decision"]        = nullptr;
    c["decision_source"] = "recomputed";
}

// The recorded decision for this row. `proxy_status` / `route_reason` keep
// their meaning for the current frontend; `decision` carries the record.
void set_recorded(nlohmann::json& c, const DecisionRecord& d, const connection_facts& f) {
    nlohmann::json j;
    j["verdict"] = d.verdict == decision_verdict::proxied ? "proxied" : "direct";
    j["reason"]  = decision_reason_name(d.reason);
    j["rule_id"] = f.rule_id.empty() ? nlohmann::json(nullptr) : nlohmann::json(f.rule_id);
    j["source"]  = d.source == decision_source::none ? nlohmann::json(nullptr)
                                                     : nlohmann::json(decision_source_name(d.source));
    j["group"]   = d.group_id == DECISION_NO_GROUP ? nlohmann::json(nullptr) : nlohmann::json(d.group_id);
    j["config_version"] = d.config_version;
    j["at_ms"]   = d.at_ms;
    j["pid"]     = d.pid;
    j["psn"]     = d.psn;
    if (d.reason == decision_reason::late) {
        j["late_verdict"] = (d.flags & decision_flags::LATE_PROXIED) ? "proxied" : "direct";
    }
    c["decision"]        = std::move(j);
    c["decision_source"] = "recorded";
    c["proxy_status"]    = recorded_proxy_status(d, f.hijacked);
    c["route_reason"]    = decision_reason_name(d.reason);
}

void set_identity(nlohmann::json& c, const connection_facts& f) {
    c["hijacked"]     = f.hijacked;
    c["pid_alive"]    = f.pid_alive;
    c["process_name"] = f.pid_alive ? f.process_name : std::string{"unknown"};
}

// v0.14 #4: optional keys, absent when there is nothing to say.
void set_conflict(nlohmann::json& c, const connection_facts& f) {
    if (f.conflict && !f.conflict->empty()) c["conflict"] = conflict_to_json(*f.conflict);
}

void set_estimate(nlohmann::json& c, const connection_facts& f) {
    if (f.current_source == decision_source::none) return;
    c["estimate"] = {
        {"source", decision_source_name(f.current_source)},
        {"rule_id", f.current_rule_id.empty() ? nlohmann::json(nullptr)
                                              : nlohmann::json(f.current_rule_id)},
    };
}

} // namespace

// A direct decision taken for a process that was proxied at the time (a
// destination / protocol exclusion, or a proxied decision that came too
// late) shows as IGNORED, as before. Reasons that do not say whether the
// process was proxied (watchdog, pool exhausted, IPv6, late direct) use the
// process's current state; the rest (self, unknown-pid, not-proxied) are
// plain direct, "-".
const char* recorded_proxy_status(const DecisionRecord& d, bool hijacked_now) noexcept {
    if (d.verdict == decision_verdict::proxied) return "PROXIED";
    switch (d.reason) {
    case decision_reason::global_exclude:
    case decision_reason::rule_exclude:
    case decision_reason::rule_exclude_port:
    case decision_reason::rule_include_cidr_miss:
    case decision_reason::rule_include_port_miss:
    case decision_reason::rule_protocol:
        return "IGNORED";
    case decision_reason::late:
        if (d.flags & decision_flags::LATE_PROXIED) return "IGNORED";
        return hijacked_now ? "IGNORED" : "-";
    case decision_reason::watchdog:
    case decision_reason::pool_exhausted:
    case decision_reason::ipv6:
        return hijacked_now ? "IGNORED" : "-";
    default:
        return "-";
    }
}

nlohmann::json conflict_to_json(const rule_conflict& c) {
    return {
        {"manual", c.manual},
        {"winner", c.winner.empty() ? nlohmann::json(nullptr) : nlohmann::json(c.winner)},
        {"shadowed_rule_ids", c.shadowed},
    };
}

nlohmann::json tcp_row_to_json(const connection_row& row, const connection_facts& f) {
    nlohmann::json c;
    c["pid"]         = row.pid;
    c["local_ip"]    = row.local_ip;
    c["local_port"]  = row.local_port;
    c["remote_ip"]   = row.remote_ip;
    c["remote_port"] = row.remote_port;
    c["state"]       = row.state;
    c["dest"]        = std::format("{}:{}", row.remote_ip, row.remote_port);
    set_identity(c, f);

    if (row.record) {
        set_recorded(c, *row.record, f);
        set_conflict(c, f);
    } else if (row.listening) {
        c["proxy_status"]    = f.hijacked ? "LISTEN" : "-";
        c["decision"]        = nullptr;
        c["decision_source"] = "none";
    } else {
        mark_recomputed(c);
        if (!f.hijacked) {
            c["proxy_status"] = "-";
        } else {
            set_fallback(c, f);
            set_estimate(c, f);
            set_conflict(c, f);
        }
    }
    return c;
}

nlohmann::json udp_row_to_json(const connection_row& row, const connection_facts& f) {
    nlohmann::json c;
    c["pid"]         = row.pid;
    c["local_ip"]    = row.local_ip;
    c["local_port"]  = row.local_port;
    c["state"]       = "BOUND";
    c["remote_ip"]   = row.remote_ip;
    c["remote_port"] = row.remote_port;
    c["dest"]        = row.remote_ip.empty() ? std::string{}
                                             : std::format("{}:{}", row.remote_ip, row.remote_port);
    set_identity(c, f);

    if (row.record) {
        set_recorded(c, *row.record, f);
        set_conflict(c, f);
        return c;
    }
    mark_recomputed(c);
    if (!f.hijacked) {
        c["proxy_status"] = "-";
    } else {
        // No destination yet: the strand evaluated only the protocol gate
        // ("none" / "rule_protocol"); otherwise route_reason for the flow.
        set_fallback(c, f);
        set_estimate(c, f);
        set_conflict(c, f);
    }
    return c;
}

nlohmann::json rows_to_json(const std::vector<connection_row>& rows,
                            const std::vector<connection_facts>& facts,
                            bool is_udp) {
    nlohmann::json arr = nlohmann::json::array();
    const std::size_t n = rows.size() < facts.size() ? rows.size() : facts.size();
    for (std::size_t i = 0; i < n; ++i) {
        arr.push_back(is_udp ? udp_row_to_json(rows[i], facts[i])
                             : tcp_row_to_json(rows[i], facts[i]));
    }
    return arr;
}

} // namespace clew
