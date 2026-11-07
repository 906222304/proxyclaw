#pragma once

// group_service — proxy group CRUD + migrate + SOCKS5 connectivity test.
//
// CRUD mutates via config_store (source of truth). delete_group refuses
// (conflict) if any auto rule or manual hijack references the group.
// migrate_group rewrites references + erases source atomically via
// cfg_.mutate + exec_.command.

#include <cstdint>

#include <nlohmann/json.hpp>

#include "domain/strand_bound.hpp"

namespace clew {

class config_store;

class group_service {
public:
    group_service(strand_bound_manager& exec, config_store& cfg);

    group_service(const group_service&)            = delete;
    group_service& operator=(const group_service&) = delete;

    [[nodiscard]] nlohmann::json list_groups() const;

    // Throws invalid_argument (400) unless a group with this id exists. Used
    // by hijack: a connection routed to a missing group would be dropped.
    void require_group(std::uint32_t id) const;

    // create/update reject (400, details.field) a port outside 1-65535, an
    // empty host or host:port, a type other than socks5, and non-empty
    // user/password (SOCKS5 auth is not implemented). See
    // config/proxy_group_validation.hpp.

    // Auto-assigns id from next_group_id. Returns the created group as json.
    [[nodiscard]] nlohmann::json create_group(const nlohmann::json& body);

    void update_group(std::uint32_t id, const nlohmann::json& patch);

    // Throws conflict (409) if the group is referenced by any auto rule or
    // any manual hijack.
    void delete_group(std::uint32_t id);

    // Rewrites all references from source_id -> target_id, reapplies rules,
    // then erases the source. Throws if source is default (0) or target is
    // missing.
    void migrate_group(std::uint32_t source_id, std::uint32_t target_id);

    // Staged SOCKS5 probe (proxy/proxy_probe.hpp), 8 s budget, at most 4
    // at once. Always HTTP 200:
    //   success {latency_ms, total_ms, detail, target, stages:[{name,ms}]}
    //   failure {error, failed_stage, total_ms, target, stages}
    // `latency_ms` present means success (legacy frontend contract).
    [[nodiscard]] nlohmann::json test_group(std::uint32_t id);

private:
    strand_bound_manager& exec_;
    config_store&         cfg_;
};

} // namespace clew
