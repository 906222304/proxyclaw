#include "services/process_tree_service.hpp"

#include <optional>
#include <string>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include "common/api_exception.hpp"
#include "common/process_tree_json.hpp"
#include "core/scoped_exit.hpp"
#include "domain/process_tree_manager.hpp"
#include "process/flat_tree.hpp"  // also declares query_process_cmdline
#include "rules/rule_engine_v3.hpp"

namespace clew {

namespace {

struct process_os_detail {
    bool same_process = true;  // false: the PID now belongs to another process
    std::string image_path;
    std::string cmdline;
    std::string package_family_name;
};

// Looks up (pid, expected_psn) in the shared cache when available, still
// verifying the live process's PSN on a cache hit so a recycled PID before ETW
// STOP never returns the previous process's cached metadata. On a cache miss,
// opens one handle, checks PSN, reads all three fields, and populates the cache.
process_os_detail query_process_detail_impl(DWORD pid, uint64_t expected_psn,
                                            process_info_cache* cache) {
    if (cache && expected_psn != INVALID_PSN) {
        if (auto cached = cache->get(pid, expected_psn, kFieldAll)) {
            const uint64_t live = query_live_psn(pid);
            if (live != INVALID_PSN && live != expected_psn) {
                cache->record_psn_mismatch();
                cache->erase(pid, expected_psn);
                return {.same_process = false};
            }
            return {true,
                    std::move(cached->image_path),
                    std::move(cached->cmdline),
                    std::move(cached->package_family_name)};
        }
    }

    auto res = query_process_info_verified(pid, expected_psn);
    if (!res.same_process) {
        if (cache && expected_psn != INVALID_PSN) {
            cache->record_psn_mismatch();
            cache->erase(pid, expected_psn);
        }
        return {.same_process = false};
    }
    if (res.opened && cache && expected_psn != INVALID_PSN) {
        cache->put(pid, expected_psn, res.info);
    }
    return {true,
            std::move(res.info.image_path),
            std::move(res.info.cmdline),
            std::move(res.info.package_family_name)};
}

} // namespace

process_tree_service::process_tree_service(strand_bound_manager& exec,
                                           process_info_cache* info_cache)
    : exec_(exec), info_cache_(info_cache) {}

nlohmann::json process_tree_service::find_process(std::uint32_t pid) const {
    std::optional<hook::status_map> statuses;
    if (hook_status_provider_) statuses = hook_status_provider_();
    const auto* hs = statuses ? &*statuses : nullptr;
    auto result = exec_.query([pid, hs](const domain::process_tree_manager& m) -> nlohmann::json {
        const auto& tree = m.tree();
        uint32_t idx = tree.find_by_pid(static_cast<DWORD>(pid));
        if (idx == INVALID_IDX) return {};
        // try_at: bounds-safe deref. Without it, a stale idx (PID-reuse race
        // or stale post-tombstone state) would deref past entries_.size()
        // and trigger 0xc0000005 + 0xffffbaad heap corruption — the
        // sticky-tree-bug wininit-1032 crash signature.
        const auto* entry = tree.try_at(idx);
        if (!entry || !entry->alive) return {};
        return process_entry_to_json(tree, m.rules(), idx, true, hs);
    });
    if (result.is_null() || result.empty()) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    return result;
}

nlohmann::json process_tree_service::find_process_detail(std::uint32_t pid,
                                                         std::optional<std::uint64_t> psn) const {
    std::optional<hook::status_map> statuses;
    if (hook_status_provider_) statuses = hook_status_provider_();
    const auto* hs = statuses ? &*statuses : nullptr;
    auto result = exec_.query([pid, hs](const domain::process_tree_manager& m) -> nlohmann::json {
        const auto& tree = m.tree();
        uint32_t idx = tree.find_by_pid(static_cast<DWORD>(pid));
        if (idx == INVALID_IDX) return {};
        const auto* entry = tree.try_at(idx);
        if (!entry || !entry->alive) return {};
        return process_entry_to_json(tree, m.rules(), idx, true, hs);
    });
    if (result.is_null() || result.empty()) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    const auto tree_psn = result["psn"].get<std::uint64_t>();
    if (psn && *psn != tree_psn) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    // OS calls run outside the strand.
    auto os = query_process_detail_impl(static_cast<DWORD>(pid), tree_psn, info_cache_);
    if (!os.same_process) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    result["image_path"] = std::move(os.image_path);
    result["cmdline"]    = std::move(os.cmdline);
    if (!os.package_family_name.empty()) {
        result["package_family_name"] = std::move(os.package_family_name);
    }
    return result;
}

nlohmann::json process_tree_service::list_hijacked() const {
    std::optional<hook::status_map> statuses;
    if (hook_status_provider_) statuses = hook_status_provider_();
    const auto* hs = statuses ? &*statuses : nullptr;
    return exec_.query([hs](const domain::process_tree_manager& m) -> nlohmann::json {
        const auto& tree  = m.tree();
        const auto& rules = m.rules();
        auto pids = rules.get_hijacked_pids(tree);
        nlohmann::json arr = nlohmann::json::array();
        for (DWORD pid : pids) {
            uint32_t idx = tree.find_by_pid(pid);
            if (idx == INVALID_IDX) continue;
            const auto* ep = tree.try_at(idx);
            if (!ep || !ep->alive) continue;
            const auto& e = *ep;
            auto match = rules.get_match_info(tree, pid);
            nlohmann::json p;
            p["pid"]            = pid;
            p["name"]           = std::string(e.name_u8);
            p["hijacked"]       = true;
            p["hijack_source"]  = hijack_source_from_match(match);
            if (const char* status = hook_status_for_entry(e, hs)) {
                p["hook_status"] = status;
            }
            arr.push_back(std::move(p));
        }
        return arr;
    });
}

void process_tree_service::hijack(std::uint32_t pid, bool tree_mode, std::uint32_t gid) {
    bool ok = exec_.command([pid, tree_mode, gid](domain::process_tree_manager& m) {
        return m.hijack_pid(static_cast<DWORD>(pid), tree_mode, gid);
    });
    if (!ok) throw api_exception{api_error::not_found, "Process not found"};
}

void process_tree_service::unhijack(std::uint32_t pid, bool tree_mode) {
    bool ok = exec_.command([pid, tree_mode](domain::process_tree_manager& m) {
        return m.unhijack_pid(static_cast<DWORD>(pid), tree_mode);
    });
    if (!ok) throw api_exception{api_error::not_found, "Process not found"};
}

nlohmann::json process_tree_service::batch_hijack(const std::vector<std::uint32_t>& pids,
                                                   std::string_view action,
                                                   std::uint32_t gid) {
    std::vector<DWORD> add_list;
    std::vector<DWORD> rm_list;
    if (action == "unhijack") {
        rm_list.reserve(pids.size());
        for (auto p : pids) rm_list.push_back(static_cast<DWORD>(p));
    } else {
        add_list.reserve(pids.size());
        for (auto p : pids) add_list.push_back(static_cast<DWORD>(p));
    }

    // tree_mode=false matches the legacy /api/hijack/batch behavior
    // (single-pid hijack, not the whole subtree).
    exec_.command([a = std::move(add_list),
                   r = std::move(rm_list),
                   gid](domain::process_tree_manager& m) mutable {
        m.batch_hijack(a, r, /*tree_mode=*/false, gid);
    });

    nlohmann::json j;
    j["success"] = true;
    j["count"]   = pids.size();
    return j;
}

} // namespace clew
