#include "services/group_service.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <semaphore>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "common/api_exception.hpp"
#include "common/json_patch.hpp"
#include "config/config_change_tag.hpp"
#include "config/config_store.hpp"
#include "config/proxy_group_validation.hpp"
#include "config/types.hpp"
#include "core/log.hpp"
#include "domain/process_tree_manager.hpp"
#include "process/flat_tree.hpp"
#include "rules/rule_engine_v3.hpp"
#include "proxy/proxy_probe.hpp"

namespace clew {

namespace {

// 400 with {"error": message, "details": {"field": ...}} for invalid input.
proxy_group_input parse_or_throw(const nlohmann::json& body) {
    proxy_group_input in;
    if (auto err = parse_proxy_group_input(body, in)) {
        throw api_exception{api_error::invalid_argument, err->message,
                            nlohmann::json{{"field", err->field}}};
    }
    return in;
}

void apply_input(ProxyGroup& g, const proxy_group_input& in) {
    if (in.name)     g.name     = *in.name;
    if (in.host)     g.host     = *in.host;
    if (in.port)     g.port     = *in.port;
    if (in.type)     g.type     = *in.type;
    if (in.test_url) g.test_url = *in.test_url;
}

} // namespace

group_service::group_service(strand_bound_manager& exec, config_store& cfg)
    : exec_(exec), cfg_(cfg) {}

nlohmann::json group_service::list_groups() const {
    const auto cfg = cfg_.get();
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& g : cfg.proxy_groups) {
        arr.push_back(nlohmann::json{
            {"id",       g.id},
            {"name",     g.name},
            {"host",     g.host},
            {"port",     g.port},
            {"type",     g.type},
            {"test_url", g.test_url},
        });
    }
    return arr;
}

nlohmann::json group_service::create_group(const nlohmann::json& body) {
    // Validate before mutating: an invalid body must not consume a group id.
    // Absent fields keep the documented defaults (127.0.0.1:7890, socks5);
    // present but invalid ones are rejected, never replaced by a default.
    const auto in = parse_or_throw(body);
    ProxyGroup group;
    cfg_.mutate(
        [&group, &in](ConfigV2& c) {
            group.id       = c.next_group_id++;
            group.name     = std::format("group_{}", group.id);
            group.host     = "127.0.0.1";
            group.port     = 7890;
            group.type     = "socks5";
            group.test_url = "http://www.gstatic.com/generate_204";
            apply_input(group, in);
            c.proxy_groups.push_back(group);
        },
        config_change::group_created);
    return group;
}

void group_service::update_group(std::uint32_t id, const nlohmann::json& patch) {
    const auto in = parse_or_throw(patch);
    bool found = false;
    cfg_.mutate(
        [&found, id, &in](ConfigV2& c) {
            for (auto& g : c.proxy_groups) {
                if (g.id == id) {
                    found = true;
                    apply_input(g, in);
                    break;
                }
            }
        },
        config_change::group_updated);

    if (!found) {
        throw api_exception{api_error::not_found, "Proxy group not found"};
    }
}

void group_service::delete_group(std::uint32_t id) {
    if (id == 0) {
        throw api_exception{api_error::invalid_argument, "Cannot delete the default proxy group"};
    }

    // Snapshot config for validation before mutating.
    auto snapshot = cfg_.get();

    auto it = std::find_if(snapshot.proxy_groups.begin(), snapshot.proxy_groups.end(),
                           [id](const ProxyGroup& g) { return g.id == id; });
    if (it == snapshot.proxy_groups.end()) {
        throw api_exception{api_error::not_found, "Proxy group not found"};
    }

    nlohmann::json referencing_rules = nlohmann::json::array();
    for (const auto& rule : snapshot.auto_rules) {
        if (rule.proxy_group_id == id) {
            referencing_rules.push_back(nlohmann::json{
                {"id",   rule.id},
                {"name", rule.name},
            });
        }
    }

    int manual_count = 0;
    try {
        manual_count = exec_.query([id](const domain::process_tree_manager& m) -> int {
            int count = 0;
            for (const auto& e : m.tree().entries()) {
                if (e.alive && e.group_id == id && e.has_flag(entry_flags::MANUAL_HIJACK)) {
                    ++count;
                }
            }
            return count;
        });
    } catch (const api_exception& e) {
        PC_LOG_WARN("[group_service] strand query failed during delete: {}", e.message());
    }

    if (!referencing_rules.empty() || manual_count > 0) {
        nlohmann::json details;
        details["auto_rules"]          = std::move(referencing_rules);
        details["manual_hijack_count"] = manual_count;
        throw api_exception{api_error::conflict, "group_in_use", std::move(details)};
    }

    cfg_.mutate(
        [id](ConfigV2& c) {
            std::erase_if(c.proxy_groups,
                          [id](const ProxyGroup& g) { return g.id == id; });
        },
        config_change::group_deleted);
}

void group_service::migrate_group(std::uint32_t source_id, std::uint32_t target_id) {
    if (source_id == 0) {
        throw api_exception{api_error::invalid_argument, "Cannot migrate the default group"};
    }

    auto snapshot = cfg_.get();
    bool source_ok = false;
    bool target_ok = false;
    for (const auto& g : snapshot.proxy_groups) {
        if (g.id == source_id) source_ok = true;
        if (g.id == target_id) target_ok = true;
    }
    if (!source_ok) throw api_exception{api_error::not_found, "Source group not found"};
    if (!target_ok) throw api_exception{api_error::invalid_argument, "Target group not found"};

    // Config side: rewrite rule.proxy_group_id and erase source group.
    cfg_.mutate(
        [source_id, target_id](ConfigV2& c) {
            for (auto& rule : c.auto_rules) {
                if (rule.proxy_group_id == source_id) {
                    rule.proxy_group_id = target_id;
                }
            }
            std::erase_if(c.proxy_groups,
                          [source_id](const ProxyGroup& g) { return g.id == source_id; });
        },
        config_change::group_migrated);

    // Runtime side: rewrite flat_tree entries' group_id.
    // (rule_engine auto rules get reapplied automatically by the config
    // observer sync, so no direct apply call needed here.)
    exec_.command([source_id, target_id](domain::process_tree_manager& m) {
        for (auto& e : m.tree().entries()) {
            if (e.alive && e.group_id == source_id && e.has_flag(entry_flags::MANUAL_HIJACK)) {
                e.group_id = target_id;
            }
        }
    });
}

void group_service::require_group(std::uint32_t id) const {
    const auto cfg = cfg_.get();
    for (const auto& g : cfg.proxy_groups) {
        if (g.id == id) return;
    }
    throw api_exception{api_error::invalid_argument,
                        std::format("Proxy group {} does not exist", id),
                        nlohmann::json{{"field", "group_id"}}};
}

nlohmann::json group_service::test_group(std::uint32_t id) {
    auto snapshot = cfg_.get();
    const ProxyGroup* group = nullptr;
    for (const auto& g : snapshot.proxy_groups) {
        if (g.id == id) { group = &g; break; }
    }
    if (!group) {
        throw api_exception{api_error::not_found, "Group not found"};
    }

    const auto target = probe::parse_test_url(group->test_url);
    if (!target) {
        return nlohmann::json{{"error", "invalid test URL"}, {"failed_stage", "config"},
                              {"stages", nlohmann::json::array()}};
    }

    // Each probe holds an HTTP worker for up to its budget; cap concurrent
    // probes so "test all" cannot starve the polling endpoints (8 workers).
    static std::counting_semaphore<4> slots{4};
    if (!slots.try_acquire_for(std::chrono::seconds(10))) {
        return nlohmann::json{{"error", "too many tests running"}, {"failed_stage", "queue"},
                              {"stages", nlohmann::json::array()}};
    }
    struct release_slot { ~release_slot() { slots.release(); } } guard;

    // Same normalisation as the relay and the UDP session resolve with.
    const std::string proxy_host = normalize_proxy_host(group->host);

    const auto r = probe::run(proxy_host, static_cast<std::uint16_t>(group->port), *target);

    nlohmann::json stages = nlohmann::json::array();
    for (const auto& st : r.stages) stages.push_back({{"name", st.name}, {"ms", st.ms}});
    nlohmann::json out{
        {"stages",   stages},
        {"total_ms", r.total_ms},
        {"target",   std::format("{}://{}:{}", target->scheme, target->host, target->port)},
    };
    if (r.ok) {
        out["latency_ms"] = r.total_ms;  // legacy field: success is latency_ms present
        out["detail"]     = r.detail;
        PC_LOG_DEBUG("[group_service] test group {}: {}ms ({}) to {}", id, r.total_ms, r.detail,
                     group->test_url);
    } else {
        out["error"]        = r.error;
        out["failed_stage"] = r.failed_stage;
        PC_LOG_INFO("[group_service] test group {} failed at {}: {} ({}ms)", id, r.failed_stage,
                    r.error, r.total_ms);
    }
    return out;
}

} // namespace clew
