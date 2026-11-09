#pragma once

// connection_rows — JSON for /api/tcp, /api/udp and /api/connections, built
// OFF the process-tree strand (ROADMAP v0.14 #3).
//
// connection_service splits one listing into three steps:
//   1. off-strand: read the OS tables into connection_row (plain strings and
//      integers), look up the UDP session destination and the DecisionRecord
//      (DecisionLog reads are lock-free and safe on any thread);
//   2. on the strand: copy the few facts that need the tree / rule engine
//      into connection_facts, one per row (pid alive, proxied, name, the
//      record's rule id, and the current-rules fallback verdict for rows
//      that have no record);
//   3. off-strand: row + facts -> JSON with the functions below.
//
// v0.14 #4 adds two optional keys: `conflict` (other enabled rules that
// also match the row's process, under the current rules) and, on recomputed
// rows, `estimate` (the rule / manual hijack that decides the process now).
//
// Step 3 is pure and std-only (no Windows, no strand), so it is unit tested
// on any platform (tests/test_connection_rows.cpp). The field set and values
// are exactly what the pre-v0.14 #3 code emitted from inside the strand.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/decision_log.hpp"
#include "rules/rule_conflict.hpp"

namespace clew {

// One OS socket, as read off-strand.
struct connection_row {
    uint32_t    pid{0};
    std::string local_ip;
    uint16_t    local_port{0};
    std::string remote_ip;          // UDP: proxied destination, "" when none seen
    uint16_t    remote_port{0};
    uint32_t    remote_addr{0};     // remote_ip parsed, host byte order (fallback input)
    std::string state;              // TCP MIB state; UDP rows are always "BOUND"
    bool        listening{false};   // TCP: LISTEN or remote 0.0.0.0:0 (no decision applies)
    std::optional<DecisionRecord> record;   // matching record, already checked against pid
};

// What the strand copies for one row.
struct connection_facts {
    bool        pid_alive{false};
    bool        hijacked{false};    // pid alive and currently proxied
    std::string process_name;       // tree name; ignored when !pid_alive ("unknown")
    std::string rule_id;            // rule id of record->policy_id ("" = none / no record)
    // Current-rules verdict, only for rows without a record whose process is
    // proxied now (computed on the strand from tree + rules). TCP: route_reason;
    // UDP without a destination: the protocol gate only.
    bool        fallback_proxied{false};
    const char* fallback_reason{nullptr};   // ip_exclude_reason_name(); nullptr = not computed
    // v0.14 #4, rows without a record whose process is proxied now: what
    // decides the process under the CURRENT rules (an estimate, emitted as
    // `estimate`). source none = not computed.
    decision_source current_source{decision_source::none};
    std::string     current_rule_id;
    // v0.14 #4: other rules that also claim the process under the CURRENT
    // rules (null = no conflict). Computed once per distinct PID on the
    // strand and shared by all of its rows.
    std::shared_ptr<const rule_conflict> conflict;
};

// A record written by a layer that knows the PID must name this row's PID;
// otherwise it belongs to an earlier socket (missed CLOSE / reused port).
[[nodiscard]] inline bool decision_record_fits(const DecisionRecord& d, uint32_t pid) noexcept {
    return d.pid == 0 || d.pid == pid;
}

// `conflict` object of a row: {"manual", "winner", "shadowed_rule_ids"}.
// Emitted only when there is a conflict (the key is absent otherwise).
[[nodiscard]] nlohmann::json conflict_to_json(const rule_conflict& c);

// The strand must compute the fallback verdict for this row (no record,
// not a listening socket, process proxied now).
[[nodiscard]] inline bool needs_fallback(const connection_row& row, bool hijacked) noexcept {
    return !row.record && !row.listening && hijacked;
}

// `proxy_status` for a recorded decision (see the .cpp for the mapping).
[[nodiscard]] const char* recorded_proxy_status(const DecisionRecord& d, bool hijacked_now) noexcept;

[[nodiscard]] nlohmann::json tcp_row_to_json(const connection_row& row, const connection_facts& f);
[[nodiscard]] nlohmann::json udp_row_to_json(const connection_row& row, const connection_facts& f);

[[nodiscard]] nlohmann::json rows_to_json(const std::vector<connection_row>& rows,
                                          const std::vector<connection_facts>& facts,
                                          bool is_udp);

} // namespace clew
