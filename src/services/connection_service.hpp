#pragma once

// connection_service — OS-level TCP/UDP connection table enriched with
// process tree + hijack status.
//
// Proxy status comes from the decision the data path recorded for the
// connection at CONNECT / BIND time (core/decision_log.hpp), not from the
// current rules: editing a rule does not rewrite what an established
// connection did. Rows without a record (opened before ProxyClaw started,
// or evicted from the bounded log) fall back to evaluating the current
// rules and say so (`decision: null`, `decision_source: "recomputed"`).
//
// Threading (v0.14 #3): the process-tree strand only copies per-row facts
// (pid alive, proxied, name, rule id, fallback verdict); OS table reads,
// UdpSessionTable / DecisionLog lookups and all JSON building run on the
// calling HTTP thread (projection/connection_rows.hpp).

#include <cstdint>
#include <optional>

#include <nlohmann/json.hpp>

#include "domain/strand_bound.hpp"

namespace clew {

class DecisionLog;
class UdpPortTracker;
class UdpSessionTable;

class connection_service {
public:
    // decisions may be null (no records: every row is recomputed).
    connection_service(strand_bound_manager& exec, UdpPortTracker* udp_tracker,
                       const UdpSessionTable* udp_sessions,
                       const DecisionLog* decisions = nullptr);

    connection_service(const connection_service&)            = delete;
    connection_service& operator=(const connection_service&) = delete;

    // GET /api/tcp?pid=X — TCP table with hijack status.
    [[nodiscard]] nlohmann::json list_tcp(std::optional<std::uint32_t> pid_filter) const;

    // GET /api/udp?pid=X — UDP table enriched with hijack status and, for ports
    // with live proxied traffic, the destination recorded in UdpSessionTable.
    [[nodiscard]] nlohmann::json list_udp(std::optional<std::uint32_t> pid_filter) const;

    // GET /api/connections?pid=X — the UI's single poll:
    //   {"tcp": [...], "udp": [...], "active_pids": [...], "config_version": N}
    // `tcp` / `udp` are exactly what /api/tcp and /api/udp return for the
    // same filter; `active_pids` (sorted) lists every PID owning a socket in
    // the UNFILTERED listing, for the process tree's activity dimming. One
    // OS table read per transport and one strand hop for both.
    // `config_version` is the engine's routing configuration version read
    // in that hop (v0.14 #4: rows decided under an older one are stale).
    [[nodiscard]] nlohmann::json list_all(std::optional<std::uint32_t> pid_filter) const;

private:
    strand_bound_manager&  exec_;
    UdpPortTracker*        udp_tracker_;
    const UdpSessionTable* udp_sessions_;
    const DecisionLog*     decisions_;
};

} // namespace clew
