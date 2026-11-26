#pragma once

// Process-tree → JSON serialization. Used by both:
//   - projection/process_projection.cpp (builds the SSE-driven snapshot)
//   - services/process_tree_service.cpp (HTTP /api/processes/:pid endpoints)
// Header-only so each translation unit gets its own inline copy; the
// functions are tiny and nlohmann::json is already a heavy include.

#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "hook/hook_status.hpp"
#include "process/flat_tree.hpp"
#include "rules/rule_engine_v3.hpp"

namespace clew {

inline std::string hijack_source_from_match(const std::optional<RuleMatchResult>& match) {
    if (!match) return {};
    if (match->rule_type == "manual")         return "manual";
    if (match->rule_type == "auto")           return "auto:" + match->rule_id;
    if (match->rule_type == "tree-inherited") return "tree:" + match->rule_id;
    return match->rule_type;
}

inline const char* hook_status_for_entry(const process_entry& e,
                                         const hook::status_map* hook_statuses) noexcept {
    if (!hook_statuses || !e.is_proxied() || e.pid <= 4) return nullptr;
    const auto it = hook_statuses->find(hook::process_key{e.pid, e.psn});
    if (it == hook_statuses->end()) return hook::inject_status_name(hook::inject_status::pending);
    return hook::inject_status_name(it->second);
}

inline nlohmann::json process_entry_to_json(const flat_tree& tree,
                                             const rule_engine_v3& rules,
                                             uint32_t idx,
                                             bool recursive,
                                             const hook::status_map* hook_statuses = nullptr) {
    const auto& e = tree.at(idx);
    auto match = rules.get_match_info(tree, e.pid);

    nlohmann::json j;
    j["pid"]            = e.pid;
    // Boot-unique process sequence number: (pid, psn) names one process even
    // after Windows reuses the PID. A counter from boot, so far below 2^53
    // and exact as a JSON / JS number.
    j["psn"]            = e.psn;
    j["parent_pid"]     = e.parent_pid;
    j["name"]           = std::string(e.name_u8);
    j["hijacked"]       = e.is_proxied();
    j["hijack_source"]  = hijack_source_from_match(match);
    if (const char* hs = hook_status_for_entry(e, hook_statuses)) {
        j["hook_status"] = hs;
    }

    if (recursive) {
        nlohmann::json children = nlohmann::json::array();
        uint32_t child = e.first_child_index;
        while (child != INVALID_IDX) {
            if (tree.at(child).alive) {
                children.push_back(process_entry_to_json(tree, rules, child, true, hook_statuses));
            }
            child = tree.at(child).next_sibling_index;
        }
        if (!children.empty()) {
            j["children"] = std::move(children);
        }
    }
    return j;
}

inline std::string process_tree_to_json_string(const flat_tree& tree,
                                                const rule_engine_v3& rules,
                                                const hook::status_map* hook_statuses = nullptr) {
    nlohmann::json arr = nlohmann::json::array();
    for (uint32_t idx : tree.get_roots()) {
        arr.push_back(process_entry_to_json(tree, rules, idx, true, hook_statuses));
    }
    return arr.dump();
}

} // namespace clew
