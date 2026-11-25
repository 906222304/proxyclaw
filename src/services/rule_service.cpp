#include "services/rule_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <unordered_set>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "common/api_exception.hpp"
#include "common/json_patch.hpp"
#include "config/config_change_tag.hpp"
#include "config/config_store.hpp"
#include "domain/process_tree_manager.hpp"
#include "process/flat_tree.hpp"
#include "rules/rule_engine_v3.hpp"

namespace clew {

namespace {

nlohmann::json rule_entry_to_json(const AutoRule& rule, const flat_tree& tree,
                                  const rule_engine_v3& engine) {
    nlohmann::json rj = rule;
    // Match and exclusion state are both keyed by (pid, psn); only live,
    // PSN-validated processes are listed so dead or recycled PIDs never leak
    // into /api/auto-rules.
    const auto excluded = engine.excluded_pids(tree, rule.id);
    const auto is_excluded = [&excluded](DWORD pid) {
        return std::binary_search(excluded.begin(), excluded.end(), pid);
    };
    nlohmann::json pids = nlohmann::json::array();
    std::unordered_set<DWORD> listed_pids;
    std::size_t live_matched = 0;
    for (const auto& pk : rule.matched_processes) {
        const uint32_t idx = tree.find_by_pid_psn(pk.pid, pk.psn);
        if (idx == INVALID_IDX || !tree.at(idx).alive) continue;
        ++live_matched;
        listed_pids.insert(pk.pid);
        nlohmann::json p;
        p["pid"]      = pk.pid;
        p["psn"]      = pk.psn;
        p["name"]     = std::string(tree.at(idx).name_u8);
        p["excluded"] = is_excluded(pk.pid);
        pids.push_back(std::move(p));
    }
    rj["matched_count"]  = live_matched;
    rj["excluded_count"] = excluded.size();
    // The engine drops an excluded process from matched_processes, so list
    // excluded processes here too (excluded=true): the UI needs them to offer 恢复代理.
    for (DWORD pid : excluded) {
        if (listed_pids.contains(pid)) continue;
        const uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX || !tree.at(idx).alive) continue;
        nlohmann::json p;
        p["pid"]      = pid;
        p["psn"]      = tree.at(idx).psn;
        p["name"]     = std::string(tree.at(idx).name_u8);
        p["excluded"] = true;
        pids.push_back(std::move(p));
    }
    rj["matched_pids"] = std::move(pids);
    return rj;
}

} // namespace

rule_service::rule_service(strand_bound_manager& exec, config_store& cfg)
    : exec_(exec), cfg_(cfg) {}

nlohmann::json rule_service::list_rules() const {
    return exec_.query([](const domain::process_tree_manager& m) -> nlohmann::json {
        const auto& tree   = m.tree();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& rule : m.rules().auto_rules()) {
            arr.push_back(rule_entry_to_json(rule, tree, m.rules()));
        }
        return arr;
    });
}

void rule_service::create_rule(AutoRule rule) {
    if (rule.id.empty()) {
        rule.id = std::format("rule_{}",
            std::chrono::steady_clock::now().time_since_epoch().count());
    }
    cfg_.mutate(
        [r = std::move(rule)](ConfigV2& c) mutable {
            c.auto_rules.push_back(std::move(r));
        },
        config_change::rule_created);
}

void rule_service::update_rule(std::string_view id, const nlohmann::json& patch) {
    bool found = false;
    cfg_.mutate(
        [&found, id, &patch](ConfigV2& c) {
            for (auto& r : c.auto_rules) {
                if (r.id == id) {
                    found = true;
                    apply_patch(r, patch,
                        field_binding{"name",               &AutoRule::name},
                        field_binding{"enabled",            &AutoRule::enabled},
                        field_binding{"process_name",        &AutoRule::process_name},
                        field_binding{"cmdline_pattern",     &AutoRule::cmdline_pattern},
                        field_binding{"image_path_pattern",  &AutoRule::image_path_pattern},
                        field_binding{"package_family_name", &AutoRule::package_family_name},
                        field_binding{"hack_tree",           &AutoRule::hack_tree},
                        field_binding{"proxy_group_id",     &AutoRule::proxy_group_id},
                        field_binding{"protocol",           &AutoRule::protocol},
                        field_binding{"proxy",              &AutoRule::proxy},
                        field_binding{"dst_filter",         &AutoRule::dst_filter},
                        field_binding{"child_exclusions",   &AutoRule::child_exclusions});
                    break;
                }
            }
        },
        config_change::rule_updated);

    if (!found) {
        throw api_exception{api_error::not_found, "Rule not found"};
    }
}

void rule_service::delete_rule(std::string_view id) {
    bool found = false;
    cfg_.mutate(
        [&found, id](ConfigV2& c) {
            auto it = std::find_if(c.auto_rules.begin(), c.auto_rules.end(),
                                   [id](const AutoRule& r) { return r.id == id; });
            if (it != c.auto_rules.end()) {
                c.auto_rules.erase(it);
                found = true;
            }
        },
        config_change::rule_deleted);

    if (!found) {
        throw api_exception{api_error::not_found, "Rule not found"};
    }
}

void rule_service::exclude_pid(std::string_view rule_id, std::uint32_t pid) {
    // Runtime-only: the engine owns exclusions keyed by (pid, psn). Nothing
    // is written to the config, so config reloads never resurrect them.
    using enum rule_engine_v3::exclude_result;
    const auto r = exec_.command([rule_id, pid](domain::process_tree_manager& m) {
        return m.exclude_rule_pid(rule_id, static_cast<DWORD>(pid));
    });
    if (r == rule_not_found) throw api_exception{api_error::not_found, "Rule not found"};
    if (r == process_not_found) throw api_exception{api_error::not_found, "Process not running"};
}

void rule_service::unexclude_pid(std::string_view rule_id, std::uint32_t pid) {
    const bool found = exec_.command([rule_id, pid](domain::process_tree_manager& m) {
        return m.unexclude_rule_pid(rule_id, static_cast<DWORD>(pid));
    });
    if (!found) {
        throw api_exception{api_error::not_found, "Rule or PID not found"};
    }
}

} // namespace clew
