#pragma once

// stats_service — aggregate runtime numbers for /api/stats and /api/env.
//
// get_stats() reads the process tree + rule engine via strand_bound_manager.
// get_env() is a pure function (no state) reading HTTP_PROXY-family env vars.

#include <functional>
#include <nlohmann/json.hpp>

#include "domain/strand_bound.hpp"

namespace clew {

class stats_service {
public:
    // traffic: optional provider of the WinDivert-layer counters (SOCKET
    // decisions, SYN parking). Supplied by app so this layer stays free of
    // the WinDivert headers; its result lands under "tcp_syn_parking".
    explicit stats_service(strand_bound_manager& exec,
                           std::function<nlohmann::json()> traffic = {});

    stats_service(const stats_service&)            = delete;
    stats_service& operator=(const stats_service&) = delete;

    // Counts of hijacked PIDs + active auto rules, plus future stats.
    [[nodiscard]] nlohmann::json get_stats() const;

    // HTTP_PROXY / HTTPS_PROXY / NO_PROXY (upper + lower case) snapshot.
    [[nodiscard]] static nlohmann::json get_env();

private:
    strand_bound_manager&           exec_;
    std::function<nlohmann::json()> traffic_;
};

} // namespace clew
