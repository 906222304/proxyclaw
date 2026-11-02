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
#include "config/types.hpp"
#include "core/log.hpp"
#include "domain/process_tree_manager.hpp"
#include "process/flat_tree.hpp"
#include "rules/rule_engine_v3.hpp"
#include "proxy/proxy_probe.hpp"

namespace clew {

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
    ProxyGroup group;
    cfg_.mutate(
        [&group, &body](ConfigV2& c) {
            group.id       = c.next_group_id++;
            group.name     = body.value("name", std::format("group_{}", group.id));
            group.host     = body.value("host", std::string{"127.0.0.1"});
            group.port     = body.value("port", 7890);
            group.type     = body.value("type", std::string{"socks5"});
            group.test_url = body.value("test_url", std::string{"http://www.gstatic.com/generate_204"});
            c.proxy_groups.push_back(group);
        },
        config_change::group_created);
    return group;
}

void group_service::update_group(std::uint32_t id, const nlohmann::json& patch) {
    bool found = false;
    cfg_.mutate(
        [&found, id, &patch](ConfigV2& c) {
            for (auto& g : c.proxy_groups) {
                if (g.id == id) {
                    found = true;
                    apply_patch(g, patch,
                        field_binding{"name",     &ProxyGroup::name},
                        field_binding{"host",     &ProxyGroup::host},
                        field_binding{"port",     &ProxyGroup::port},
                        field_binding{"type",     &ProxyGroup::type},
                        field_binding{"test_url", &ProxyGroup::test_url});
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

    std::string proxy_host = group->host;
    if (proxy_host.size() > 2 && proxy_host.front() == '[' && proxy_host.back() == ']')
        proxy_host = proxy_host.substr(1, proxy_host.size() - 2);

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
