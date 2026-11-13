#pragma once

// Rule Engine v3: operates directly on flat_tree entries.
// All functions run on the strand — no internal mutex.
//
// Priority: Manual hijack > Auto rules (config order) > DIRECT
// hack_tree: LC-RS descendant traversal (O(subtree) vs v1's iterative O(N))
//
// SOCKET handler reads entry.group_id directly (hot path, O(1)).
// Rule engine sets group_id/flags when processes start or rules change.

#include <string>
#include <string_view>
#include <format>
#include <memory>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <algorithm>
#include "core/log.hpp"
#include "core/string_hash.hpp"

#include "process/flat_tree.hpp"
#include "config/types.hpp"
#include "core/decision_log.hpp"
#include "rules/traffic_filter.hpp"
#include "rules/policy_table.hpp"
#include "rules/rule_conflict.hpp"

namespace clew {

// ============================================================
// Wildcard matching (from v1 rule_engine, case-insensitive)
// ============================================================

inline bool wildcard_match(std::string_view pattern, std::string_view text,
                           bool case_insensitive = true)
{
    auto to_lower = [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };

    size_t pi = 0;
    size_t ti = 0;
    size_t star_pi = std::string_view::npos;
    size_t star_ti = 0;

    while (ti < text.size()) {
        if (pi < pattern.size()) {
            char pc = case_insensitive ? to_lower(pattern[pi]) : pattern[pi];
            char tc = case_insensitive ? to_lower(text[ti]) : text[ti];

            if (pc == '?') { pi++; ti++; continue; }
            if (pc == '*') { star_pi = pi++; star_ti = ti; continue; }
            if (pc == tc)  { pi++; ti++; continue; }
        }
        if (star_pi != std::string_view::npos) {
            pi = star_pi + 1;
            ti = ++star_ti;
            continue;
        }
        return false;
    }
    while (pi < pattern.size() && pattern[pi] == '*') pi++;
    return pi == pattern.size();
}

// ============================================================
// Cmdline matching: auto-selects keyword vs glob mode
//   - Keyword mode (no * or ?): split by space, all fragments must be
//     case-insensitive substrings of cmdline, order-independent
//   - Glob mode (has * or ?): full wildcard match, order-sensitive
// ============================================================

inline bool cmdline_match(std::string_view pattern, std::string_view cmdline) {
    // Detect mode: glob if pattern contains * or ?
    if (pattern.find_first_of("*?") != std::string_view::npos) {
        return wildcard_match(pattern, cmdline);
    }

    // Keyword mode: all space-separated fragments must be substrings (case-insensitive)
    auto to_lower_str = [](std::string_view s) {
        std::string r{s};
        for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return r;
    };

    std::string lower_cmdline = to_lower_str(cmdline);
    std::string lower_pattern = to_lower_str(pattern);

    size_t pos = 0;
    while (pos < lower_pattern.size()) {
        // Skip spaces
        while (pos < lower_pattern.size() && lower_pattern[pos] == ' ') pos++;
        if (pos >= lower_pattern.size()) break;

        // Extract fragment
        size_t end = lower_pattern.find(' ', pos);
        if (end == std::string::npos) end = lower_pattern.size();
        std::string_view fragment{lower_pattern.data() + pos, end - pos};
        pos = end;

        // Each fragment must appear somewhere in cmdline
        if (lower_cmdline.find(fragment) == std::string::npos) return false;
    }
    return true;
}

// Route reason -> decision record reason (same names, see decision_log.hpp).
inline decision_reason to_decision_reason(IpExcludeReason r) noexcept {
    switch (r) {
    case IpExcludeReason::global:            return decision_reason::global_exclude;
    case IpExcludeReason::rule:              return decision_reason::rule_exclude;
    case IpExcludeReason::rule_port:         return decision_reason::rule_exclude_port;
    case IpExcludeReason::include_cidr_miss: return decision_reason::rule_include_cidr_miss;
    case IpExcludeReason::include_port_miss: return decision_reason::rule_include_port_miss;
    case IpExcludeReason::protocol:          return decision_reason::rule_protocol;
    default:                                 return decision_reason::none;
    }
}

// ============================================================
// Rule match result (for API / tracker)
// ============================================================

struct RuleMatchResult {
    std::string rule_id;
    std::string rule_type;  // "manual" | "auto" | "tree-inherited"
    uint32_t group_id{0};
};

// ============================================================
// Rule Engine v3
// ============================================================

class rule_engine_v3 {
public:
    rule_engine_v3() = default;

    // Load auto rules from config (called on strand). Per-process exclusions
    // are engine-owned runtime state (see exclusions_) and survive a reload
    // for every rule id that still exists; nothing about them is read from
    // or written to the config.
    void set_auto_rules(const std::vector<AutoRule>& rules) {
        ++config_version_;
        auto_rules_ = rules;
        std::erase_if(exclusions_, [this](const auto& kv) {
            return std::none_of(auto_rules_.begin(), auto_rules_.end(),
                                [&kv](const AutoRule& r) { return r.id == kv.first; });
        });
        for (auto& r : auto_rules_) {
            r.matched_pids.clear();
            // v0.9.0: hack_tree pinned true; field retained on disk for future
            // per-rule single-node mode but never honored at runtime.
            r.hack_tree = true;
            assign_policy_id(r.id);
        }
        refresh_cmdline_flag();
    }

    // Monotonic counter of the routing configuration this engine applies:
    // bumped on every rule / exclude-CIDR reload (any config change but
    // window geometry goes through set_auto_rules) and on every manual
    // hijack change. Strand-owned. Stamped into each decision record so the
    // UI can tell a decision made under an older configuration.
    [[nodiscard]] uint64_t config_version() const noexcept { return config_version_; }

    // Where a live entry's proxy state comes from, for the decision record.
    // Same first-match ordering as get_match_info() / route_reason(). Cost:
    // one matched_pids lookup per rule up to the match, then one map lookup.
    struct decision_origin {
        decision_source source{decision_source::none};
        uint32_t        policy_id{0};   // 0 = no rule (manual, none)
    };
    [[nodiscard]] decision_origin origin_of(const process_entry& entry) const {
        if (!entry.is_proxied()) return {};
        if (entry.has_flag(entry_flags::MANUAL_HIJACK)) return {decision_source::manual, 0};
        for (const auto& rule : auto_rules_) {
            if (!rule.matched_pids.contains(entry.pid)) continue;
            auto it = policy_ids_.find(rule.id);
            return {entry.has_flag(entry_flags::TREE_INHERITED) ? decision_source::tree
                                                                : decision_source::rule,
                    it == policy_ids_.end() ? 0u : it->second};
        }
        return {};
    }

    // Every source that claims this live entry beyond the one that decides
    // it (ROADMAP v0.14 #4): the enabled rules whose matched_pids hold the
    // PID, in config order, the first being the winner unless the entry is
    // manually hijacked. Both apply_auto_rules() and on_process_start()
    // evaluate every rule, so a shadowed rule still lists the PID. Cost: one
    // matched_pids lookup per rule; strand only. Empty when there is no
    // conflict.
    [[nodiscard]] rule_conflict conflict_of(const process_entry& entry) const {
        if (!entry.alive || !entry.is_proxied()) return {};
        std::vector<std::string> matching;
        for (const auto& rule : auto_rules_) {
            if (rule.enabled && rule.matched_pids.contains(entry.pid)) matching.push_back(rule.id);
        }
        return make_rule_conflict(entry.has_flag(entry_flags::MANUAL_HIJACK), std::move(matching));
    }

    // Rule id for a runtime policy id. Policy ids are never reused, so this
    // still names a rule that has since been deleted. Empty for 0 / unknown.
    [[nodiscard]] std::string rule_id_for_policy(uint32_t policy_id) const {
        if (policy_id == 0) return {};
        for (const auto& [id, pid] : policy_ids_)
            if (pid == policy_id) return id;
        return {};
    }

    std::vector<AutoRule>& auto_rules() { return auto_rules_; }
    const std::vector<AutoRule>& auto_rules() const { return auto_rules_; }

    // ---- Manual hijack (strand-safe) ----

    void manual_hijack(flat_tree& tree, DWORD pid, uint32_t group_id) {
        ++config_version_;
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return;

        auto& entry = tree.at(idx);
        entry.group_id = group_id;
        entry.set_flag(entry_flags::MANUAL_HIJACK);

        PC_LOG_INFO("[RULE] Manual hijack: PID={} group={}", pid, group_id);
    }

    void manual_unhijack(flat_tree& tree, DWORD pid) {
        ++config_version_;
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return;

        auto& entry = tree.at(idx);
        entry.clear_flag(entry_flags::MANUAL_HIJACK);

        // If not auto-matched either, clear group_id
        if (!entry.has_flag(entry_flags::AUTO_MATCHED)) {
            entry.group_id = NO_PROXY;
        }

        PC_LOG_INFO("[RULE] Manual unhijack: PID={}", pid);
    }

    // Manual hijack with tree expansion: sets MANUAL_HIJACK on target + all descendants
    void manual_hijack_tree(flat_tree& tree, DWORD pid, uint32_t group_id) {
        ++config_version_;
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return;

        tree.at(idx).group_id = group_id;
        tree.at(idx).set_flag(entry_flags::MANUAL_HIJACK);

        tree.visit_descendants(idx, [&tree, group_id](uint32_t ci, const process_entry&) {
            auto& c = tree.at(ci);
            c.group_id = group_id;
            c.set_flag(entry_flags::MANUAL_HIJACK);
        });

        PC_LOG_INFO("[RULE] Manual hijack tree: PID={} group={}", pid, group_id);
    }

    // Manual unhijack with cascade: clears MANUAL_HIJACK on target + all descendants
    void manual_unhijack_tree(flat_tree& tree, DWORD pid) {
        ++config_version_;
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return;

        auto& entry = tree.at(idx);
        entry.clear_flag(entry_flags::MANUAL_HIJACK);
        if (!entry.has_flag(entry_flags::AUTO_MATCHED)) entry.group_id = NO_PROXY;

        tree.visit_descendants(idx, [&tree](uint32_t ci, const process_entry& child) {
            if (!child.has_flag(entry_flags::MANUAL_HIJACK)) return;
            auto& c = tree.at(ci);
            c.clear_flag(entry_flags::MANUAL_HIJACK);
            if (!c.has_flag(entry_flags::AUTO_MATCHED)) c.group_id = NO_PROXY;
        });

        PC_LOG_INFO("[RULE] Manual unhijack tree: PID={}", pid);
    }

    bool is_manually_hijacked(const flat_tree& tree, DWORD pid) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return false;
        return tree.at(idx).has_flag(entry_flags::MANUAL_HIJACK);
    }

    // ---- Auto rule matching (strand-safe) ----

    // Full scan: apply all auto rules to entire tree.
    // Called on rule changes or initial setup.
    void apply_auto_rules(flat_tree& tree) {
        refresh_cmdline_flag();
        // Clear all auto-match state first
        for (auto& entry : tree.entries()) {
            if (!entry.alive) continue;
            entry.clear_flag(entry_flags::TREE_INHERITED);
            if (entry.has_flag(entry_flags::AUTO_MATCHED)) {
                entry.clear_flag(entry_flags::AUTO_MATCHED);
                if (!entry.has_flag(entry_flags::MANUAL_HIJACK)) {
                    entry.group_id = NO_PROXY;
                }
            }
        }
        for (auto& rule : auto_rules_) {
            rule.matched_pids.clear();
        }

        // Apply each rule
        for (auto& rule : auto_rules_) {
            if (!rule.enabled) continue;
            apply_single_rule(tree, rule);
        }
    }

    // Check a newly started process against auto rules.
    // Called from ETW ProcessStart handler.
    std::optional<std::string> on_process_start(flat_tree& tree, uint32_t idx) {
        const auto& entry = tree.at(idx);
        if (!entry.alive) return std::nullopt;
        std::string name(entry.name_u8);

        // Every rule is evaluated, as apply_auto_rules() does, so a rule
        // shadowed by an earlier one still lists the process in its
        // matched_pids (conflict_of() reads that). The first match in config
        // order decides the process (mark_proxied keeps it).
        const AutoRule* first = nullptr;
        bool first_inherited = false;
        for (auto& rule : auto_rules_) {
            auto kind = try_match_one(tree, idx, rule);
            if (!kind.name && !kind.tree) continue;

            rule.matched_pids.insert(entry.pid);
            mark_proxied(tree, idx, rule, /*inherited=*/kind.tree);
            // For hack_tree name matches: also expand to all existing descendants.
            if (kind.name && rule.hack_tree) {
                expand_descendants(tree, idx, rule);
            }
            if (!first) { first = &rule; first_inherited = kind.tree; }
        }
        if (first) {
            PC_LOG_INFO("[RULE] {} PID={} ({}) → rule '{}' group={}",
                         first_inherited ? "Tree-inherited" : "Auto-matched",
                         entry.pid, name, first->name, first->proxy_group_id);
            return first->id;
        }

        // No auto rule matched — try manual hijack inheritance from parent.
        if (DWORD parent_pid = try_inherit_manual(tree, idx); parent_pid != 0) {
            PC_LOG_INFO("[RULE] Manual tree-inherit: PID={} ({}) from parent PID={}",
                         entry.pid, name, parent_pid);
            return std::format("manual:tree:{}", parent_pid);
        }
        return std::nullopt;
    }

    // Process exit (or its PID was recycled before the STOP arrived): drop
    // every piece of per-PID rule state of the old owner.
    void on_process_exit(DWORD pid) {
        for (auto& rule : auto_rules_) {
            rule.matched_pids.erase(pid);
        }
        for (auto& [rule_id, by_pid] : exclusions_) by_pid.erase(pid);
        std::erase_if(exclusions_, [](const auto& kv) { return kv.second.empty(); });
    }

    // ---- Per-process exclusion (runtime only, strand-safe) ----
    //
    // "This process skips rule X." Keyed by (pid, psn) of the live process
    // when the user excluded it, never persisted and never copied from the
    // config. A lookup only honours an exclusion whose PSN is the tree
    // entry's current PSN, so a recycled PID is not excluded even if the
    // STOP of its predecessor was lost. Dropped on process exit.

    enum class exclude_result { ok, rule_not_found, process_not_found };

    // Callers re-apply the rules afterwards (apply_auto_rules) so the tree
    // flags and matched sets reflect the exclusion.
    exclude_result exclude_pid(const flat_tree& tree, std::string_view rule_id, DWORD pid) {
        if (!find_rule(rule_id)) return exclude_result::rule_not_found;
        const uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX || !tree.at(idx).alive) return exclude_result::process_not_found;
        exclusions_[std::string(rule_id)][pid] = tree.at(idx).psn;
        return exclude_result::ok;
    }

    // False when the rule has no exclusion for this PID.
    bool unexclude_pid(std::string_view rule_id, DWORD pid) {
        auto it = exclusions_.find(rule_id);
        if (it == exclusions_.end()) return false;
        const bool erased = it->second.erase(pid) > 0;
        if (it->second.empty()) exclusions_.erase(it);
        return erased;
    }

    // Is this live entry excluded from the rule? Validates the PSN.
    [[nodiscard]] bool is_excluded(std::string_view rule_id, const process_entry& entry) const {
        if (exclusions_.empty()) return false;
        auto it = exclusions_.find(rule_id);
        if (it == exclusions_.end()) return false;
        auto pit = it->second.find(entry.pid);
        return pit != it->second.end() && pit->second == entry.psn && entry.alive;
    }

    // Live, validated excluded PIDs of one rule (API listing).
    [[nodiscard]] std::vector<DWORD> excluded_pids(const flat_tree& tree,
                                                   std::string_view rule_id) const {
        std::vector<DWORD> out;
        auto it = exclusions_.find(rule_id);
        if (it == exclusions_.end()) return out;
        for (const auto& [pid, psn] : it->second) {
            const uint32_t idx = tree.find_by_pid(pid);
            if (idx == INVALID_IDX) continue;
            if (is_excluded(rule_id, tree.at(idx))) out.push_back(pid);
        }
        std::sort(out.begin(), out.end());
        return out;
    }

    // Stored exclusion count across all rules, valid or not (tests/diagnostics).
    [[nodiscard]] std::size_t exclusion_count() const {
        std::size_t n = 0;
        for (const auto& [id, by_pid] : exclusions_) n += by_pid.size();
        return n;
    }

    // Get hijacked PIDs (for API)
    std::vector<DWORD> get_hijacked_pids(const flat_tree& tree) const {
        std::vector<DWORD> result;
        for (const auto& entry : tree.entries()) {
            if (entry.alive && entry.is_proxied()) {
                result.push_back(entry.pid);
            }
        }
        return result;
    }

    // Find which rule matched a PID (for API display)
    // Check if a PID should be proxied for a specific protocol ("tcp" or "udp").
    // Manual hijack always matches both protocols.
    bool should_proxy_protocol(const flat_tree& tree, DWORD pid, std::string_view proto) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return false;
        const auto& entry = tree.at(idx);
        if (!entry.alive || !entry.is_proxied()) return false;

        // Manual hijack: always proxy both TCP and UDP
        if (entry.has_flag(entry_flags::MANUAL_HIJACK)) return true;

        // Auto rule: check protocol field
        for (const auto& rule : auto_rules_) {
            if (rule.matched_pids.contains(pid)) {
                if (proto == "tcp") return rule.matches_tcp();
                if (proto == "udp") return rule.matches_udp();
                return true;
            }
        }
        return false;
    }

    void set_default_exclude_cidrs(const std::vector<std::string>& cidrs) {
        default_exclude_cidrs_.clear();
        default_exclude_cidrs_.reserve(cidrs.size());
        for (const auto& cidr : cidrs) {
            default_exclude_cidrs_.push_back(CidrRange::parse(cidr));
        }
    }

    // The rule filter that applies to a proxied pid, or null when only the
    // global excludes apply (manual hijack, unknown pid, no matching rule).
    // Same first-match ordering as get_match_info().
    [[nodiscard]] const TrafficFilter* rule_filter_for(const flat_tree& tree, DWORD pid) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return nullptr;
        const auto& entry = tree.at(idx);
        if (!entry.alive || !entry.is_proxied() ||
            entry.has_flag(entry_flags::MANUAL_HIJACK)) {
            return nullptr;
        }
        for (const auto& rule : auto_rules_) {
            if (rule.matched_pids.contains(pid)) return &rule.dst_filter;
        }
        return nullptr;
    }

    // Capture the destination policy for a proxied process.
    [[nodiscard]] IpExcludePolicy ip_exclude_policy(const flat_tree& tree, DWORD pid) const {
        IpExcludePolicy policy;
        policy.global_cidrs = default_exclude_cidrs_;
        if (const auto* filter = rule_filter_for(tree, pid)) policy.rule = *filter;
        return policy;
    }

    // Runtime policy id for a proxied process. Same first-match ordering as
    // ip_exclude_policy(); manual hijacks and unmatched pids get row 0.
    [[nodiscard]] uint32_t policy_id_for(const flat_tree& tree, DWORD pid) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return GLOBAL_ONLY_POLICY;
        const auto& entry = tree.at(idx);
        if (!entry.alive || !entry.is_proxied() ||
            entry.has_flag(entry_flags::MANUAL_HIJACK)) {
            return GLOBAL_ONLY_POLICY;
        }

        for (const auto& rule : auto_rules_) {
            if (rule.matched_pids.contains(pid)) {
                auto it = policy_ids_.find(rule.id);
                return it == policy_ids_.end() ? GLOBAL_ONLY_POLICY : it->second;
            }
        }
        return GLOBAL_ONLY_POLICY;
    }

    // Build the immutable table published to the NETWORK workers. Rows whose
    // rule no longer exists stay at "global excludes only", so a socket that
    // outlives its rule degrades to the global policy instead of picking up
    // some other rule's excludes.
    [[nodiscard]] std::shared_ptr<const PolicyTable> build_policy_table() const {
        auto table = std::make_shared<PolicyTable>();
        table->rows.assign(next_policy_id_, IpExcludePolicy{});
        for (auto& row : table->rows) row.global_cidrs = default_exclude_cidrs_;

        for (const auto& rule : auto_rules_) {
            auto it = policy_ids_.find(rule.id);
            if (it == policy_ids_.end()) continue;
            table->rows[it->second].rule = rule.dst_filter;
        }
        return table;
    }

    // Destination verdict for a proxied pid: global excludes, then the
    // matched rule's dst_filter (exclude CIDR/port, include CIDR/port).
    [[nodiscard]] IpExcludeReason ip_exclude_reason(const flat_tree& tree,
                                                     DWORD pid,
                                                     uint32_t dest_ip,
                                                     uint16_t dest_port) const {
        return evaluate_destination(default_exclude_cidrs_, rule_filter_for(tree, pid),
                                    dest_ip, dest_port);
    }

    // Full verdict for one flow: the rule's protocol field, then the
    // destination checks. The TCP SOCKET layer and the connection list both
    // call this, so the UI reports what the data path decided.
    //
    // A proxied, non-manual pid with no matching rule (a transient state while
    // rules are rebuilt) keeps the historical behaviour of each transport:
    // TCP falls back to global excludes only, UDP is not proxied (that is what
    // should_proxy_protocol() answers for it).
    [[nodiscard]] IpExcludeReason route_reason(const flat_tree& tree,
                                               DWORD pid,
                                               bool is_udp,
                                               uint32_t dest_ip,
                                               uint16_t dest_port) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx != INVALID_IDX) {
            const auto& entry = tree.at(idx);
            if (entry.alive && entry.is_proxied() &&
                !entry.has_flag(entry_flags::MANUAL_HIJACK)) {
                for (const auto& rule : auto_rules_) {
                    if (!rule.matched_pids.contains(pid)) continue;
                    if (!(is_udp ? rule.matches_udp() : rule.matches_tcp())) {
                        return IpExcludeReason::protocol;
                    }
                    return evaluate_destination(default_exclude_cidrs_, &rule.dst_filter,
                                                dest_ip, dest_port);
                }
                if (is_udp) return IpExcludeReason::protocol;
            }
        }
        return evaluate_destination(default_exclude_cidrs_, nullptr, dest_ip, dest_port);
    }

    // route_reason() for an IPv6 destination (evaluate_destination_v6):
    // decides whether a proxied process's IPv6 flow is blocked.
    [[nodiscard]] IpExcludeReason route_reason_v6(const flat_tree& tree,
                                                  DWORD pid,
                                                  bool is_udp,
                                                  bool local_scope,
                                                  uint16_t dest_port) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx != INVALID_IDX) {
            const auto& entry = tree.at(idx);
            if (entry.alive && entry.is_proxied() &&
                !entry.has_flag(entry_flags::MANUAL_HIJACK)) {
                for (const auto& rule : auto_rules_) {
                    if (!rule.matched_pids.contains(pid)) continue;
                    if (!(is_udp ? rule.matches_udp() : rule.matches_tcp())) {
                        return IpExcludeReason::protocol;
                    }
                    return evaluate_destination_v6(local_scope, &rule.dst_filter, dest_port);
                }
                if (is_udp) return IpExcludeReason::protocol;
            }
        }
        return evaluate_destination_v6(local_scope, nullptr, dest_port);
    }

    std::optional<RuleMatchResult> get_match_info(const flat_tree& tree, DWORD pid) const {
        uint32_t idx = tree.find_by_pid(pid);
        if (idx == INVALID_IDX) return std::nullopt;

        const auto& entry = tree.at(idx);
        if (!entry.is_proxied()) return std::nullopt;

        RuleMatchResult result;
        result.group_id = entry.group_id;

        if (entry.has_flag(entry_flags::MANUAL_HIJACK)) {
            result.rule_type = "manual";
            result.rule_id = std::format("manual:{}", pid);
            return result;
        }

        // Find which auto rule matched this PID
        for (const auto& rule : auto_rules_) {
            if (rule.matched_pids.contains(pid)) {
                result.rule_type = "auto";
                result.rule_id = rule.id;
                return result;
            }
        }

        return std::nullopt;
    }

private:
    std::vector<AutoRule> auto_rules_;
    // rule id -> pid -> psn of the excluded process (see exclude_pid).
    string_map<std::unordered_map<DWORD, uint64_t>> exclusions_;

    const AutoRule* find_rule(std::string_view rule_id) const {
        for (const auto& r : auto_rules_) if (r.id == rule_id) return &r;
        return nullptr;
    }
    std::vector<CidrRange> default_exclude_cidrs_;
    bool any_rule_uses_cmdline_ = false;
    uint64_t config_version_ = 0;

    // Rule id -> runtime policy id. Handed out from 1 (0 is reserved) and never
    // reused: tracker slots hold the number, so recycling it would silently
    // point a live socket at some other rule's excludes. An index into
    // auto_rules_ would have the same problem — it shifts on add/remove.
    // Monotonic within a session; tracker entries do not outlive the process.
    std::unordered_map<std::string, uint32_t> policy_ids_;
    uint32_t next_policy_id_ = 1;

    void assign_policy_id(const std::string& rule_id) {
        if (rule_id.empty()) return;
        if (policy_ids_.try_emplace(rule_id, next_policy_id_).second) {
            ++next_policy_id_;
        }
    }

    void refresh_cmdline_flag() {
        any_rule_uses_cmdline_ = std::any_of(auto_rules_.begin(), auto_rules_.end(),
            [](const AutoRule& r) { return !r.cmdline_pattern.empty(); });
    }

    // Lazy cmdline check: returns true if cmdline matches (or rule has no cmdline_pattern).
    // Queries OS on first call per process, caches result in entry.cmdline_cache.
    // Sentinel "\x01" means "queried but empty/failed" — avoids repeated syscalls.
    bool check_cmdline(flat_tree& tree, uint32_t idx, const AutoRule& rule) {
        if (rule.cmdline_pattern.empty()) return true;

        auto& entry = tree.at(idx);
        if (entry.cmdline_cache.empty()) {
            entry.cmdline_cache = query_process_cmdline(entry.pid);
            if (entry.cmdline_cache.empty()) {
                entry.cmdline_cache = "\x01";  // sentinel: queried but failed/empty
            }
        }
        return entry.cmdline_cache[0] != '\x01' &&
               cmdline_match(rule.cmdline_pattern, entry.cmdline_cache);
    }

    // Lazy image_path check: prefix match (case-insensitive).
    // Only queries OS if rule has image_path_pattern and name already matched.
    bool check_image_path(flat_tree& tree, uint32_t idx, const AutoRule& rule) {
        if (rule.image_path_pattern.empty()) return true;

        auto& entry = tree.at(idx);
        if (entry.image_path_cache.empty()) {
            entry.image_path_cache = query_process_image_path(entry.pid);
            if (entry.image_path_cache.empty()) {
                entry.image_path_cache = "\x01";
            }
        }
        if (entry.image_path_cache[0] == '\x01') return false;

        const auto& path = entry.image_path_cache;
        const auto& pattern = rule.image_path_pattern;
        if (path.size() < pattern.size()) return false;
        return std::equal(pattern.begin(), pattern.end(), path.begin(),
            [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) ==
                       std::tolower(static_cast<unsigned char>(b));
            });
    }

    // Per-entry match decision against a single rule. Pure (no side effects).
    // - name: entry passes process_name + cmdline + image_path filters
    // - tree: entry inherits via parent already in matched_pids (hack_tree only)
    // Both false → no match. Empty process_name never name-matches; cmdline /
    // image_path are filters on top of the name match (matches the documented
    // semantics in README).
    struct match_kind { bool name = false; bool tree = false; };

    match_kind try_match_one(flat_tree& tree, uint32_t idx, const AutoRule& rule) {
        const auto& entry = tree.at(idx);
        if (!rule.enabled) return {};
        if (!entry.alive) return {};
        if (is_excluded(rule.id, entry)) return {};
        if (rule.matched_pids.contains(entry.pid)) return {};

        const bool name_match =
            !rule.process_name.empty()
            && wildcard_match(rule.process_name, entry.name_u8)
            && check_cmdline(tree, idx, rule)
            && check_image_path(tree, idx, rule);

        const bool tree_match =
            !name_match && rule.hack_tree && entry.parent_pid != 0
            && rule.matched_pids.contains(entry.parent_pid);

        return {name_match, tree_match};
    }

    // If parent has MANUAL_HIJACK, propagate group_id + flag to child.
    // Returns parent_pid on success, 0 if no inheritance happened.
    DWORD try_inherit_manual(flat_tree& tree, uint32_t idx) {
        const auto& entry = tree.at(idx);
        if (entry.parent_pid == 0) return 0;
        uint32_t parent_idx = tree.find_by_pid(entry.parent_pid);
        if (parent_idx == INVALID_IDX) return 0;
        const auto& parent = tree.at(parent_idx);
        if (!parent.alive || !parent.has_flag(entry_flags::MANUAL_HIJACK)) return 0;

        auto& child = tree.at(idx);
        child.group_id = parent.group_id;
        child.set_flag(entry_flags::MANUAL_HIJACK);
        return entry.parent_pid;
    }

    // Apply a single auto rule to all alive entries.
    // Phase 1: collect direct name matches. Phase 2 (hack_tree only): expand
    // from roots whose parent is NOT itself name-matched, so each name-matched
    // chain has exactly one expansion root.
    void apply_single_rule(flat_tree& tree, AutoRule& rule) {
        std::unordered_set<DWORD> name_matched;

        for (uint32_t i = 0; i < tree.entries().size(); i++) {
            // Bulk apply only cares about direct name matches; hack_tree
            // expansion is handled in phase 2 from name_matched roots.
            if (!try_match_one(tree, i, rule).name) continue;

            const DWORD pid = tree.entries()[i].pid;
            if (rule.hack_tree) {
                name_matched.insert(pid);
            } else {
                rule.matched_pids.insert(pid);
                mark_proxied(tree, i, rule, /*inherited=*/false);
            }
        }

        if (rule.hack_tree) {
            for (DWORD pid : name_matched) {
                uint32_t idx = tree.find_by_pid(pid);
                if (idx == INVALID_IDX) continue;
                const auto& entry = tree.at(idx);

                rule.matched_pids.insert(pid);
                mark_proxied(tree, idx, rule, /*inherited=*/false);
                if (!name_matched.contains(entry.parent_pid)) {
                    expand_descendants(tree, idx, rule);
                }
            }
        }

        if (!rule.matched_pids.empty()) {
            PC_LOG_INFO("[RULE] '{}': {} processes matched", rule.name, rule.matched_pids.size());
        }
    }

    // Expand all descendants of an entry via LC-RS traversal
    void expand_descendants(flat_tree& tree, uint32_t idx, AutoRule& rule) {
        tree.visit_descendants(idx, [this, &tree, &rule](uint32_t child_idx, const process_entry& child) {
            if (is_excluded(rule.id, child)) return;
            if (rule.matched_pids.contains(child.pid)) return;
            rule.matched_pids.insert(child.pid);
            mark_proxied(tree, child_idx, rule, /*inherited=*/true);
        });
    }

    // Set group_id and AUTO_MATCHED flag on an entry
    // `inherited`: matched through a rule-matched ancestor (hack_tree), not
    // by its own name. Labels the decision record's source only.
    //
    // Callers insert the PID into rule.matched_pids first. The rule that
    // decides the entry is the first one in config order whose matched_pids
    // holds the PID: that is what origin_of(), route_reason(), the policy id
    // and conflict_of() report, so its proxy group and kind of match are the
    // ones stored. A later (shadowed) rule leaves the entry alone. Before
    // v0.14 #4 a bulk apply let the LAST matching rule's group win while the
    // first rule's destination filter applied.
    void mark_proxied(flat_tree& tree, uint32_t idx, const AutoRule& rule, bool inherited) {
        auto& entry = tree.at(idx);
        // Don't overwrite manual hijack
        if (entry.has_flag(entry_flags::MANUAL_HIJACK)) return;
        if (entry.has_flag(entry_flags::AUTO_MATCHED)) {
            for (const auto& r : auto_rules_) {
                if (&r == &rule) break;                                // rule precedes every other claimant
                if (r.matched_pids.contains(entry.pid)) return;       // an earlier rule decides it
            }
        }
        if (inherited) entry.set_flag(entry_flags::TREE_INHERITED);
        else           entry.clear_flag(entry_flags::TREE_INHERITED);
        entry.group_id = rule.proxy_group_id;
        entry.set_flag(entry_flags::AUTO_MATCHED);
    }
};

} // namespace clew
