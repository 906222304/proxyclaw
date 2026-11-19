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
};

// Opens the process once and keeps the handle for every read: an open handle
// pins the process object, so its PID cannot be reused mid-query. The PSN is
// checked first; a mismatch means the tree entry's process has exited and
// the PID was recycled before its ETW STOP arrived.
process_os_detail query_process_detail_impl(DWORD pid, uint64_t expected_psn) {
    auto h = wrap_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h) return {};  // gone or protected: tree facts only, as before
    const uint64_t live = query_process_psn(h.get());
    if (live != INVALID_PSN && live != expected_psn) return {.same_process = false};
    return {true, query_process_image_path(h.get()), query_process_cmdline(h.get())};
}

} // namespace

process_tree_service::process_tree_service(strand_bound_manager& exec)
    : exec_(exec) {}

nlohmann::json process_tree_service::find_process(std::uint32_t pid) const {
    auto result = exec_.query([pid](const domain::process_tree_manager& m) -> nlohmann::json {
        const auto& tree = m.tree();
        uint32_t idx = tree.find_by_pid(static_cast<DWORD>(pid));
        if (idx == INVALID_IDX) return {};
        // try_at: bounds-safe deref. Without it, a stale idx (PID-reuse race
        // or stale post-tombstone state) would deref past entries_.size()
        // and trigger 0xc0000005 + 0xffffbaad heap corruption — the
        // sticky-tree-bug wininit-1032 crash signature.
        const auto* entry = tree.try_at(idx);
        if (!entry || !entry->alive) return {};
        return process_entry_to_json(tree, m.rules(), idx, true);
    });
    if (result.is_null() || result.empty()) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    return result;
}

nlohmann::json process_tree_service::find_process_detail(std::uint32_t pid,
                                                         std::optional<std::uint64_t> psn) const {
    auto result = exec_.query([pid](const domain::process_tree_manager& m) -> nlohmann::json {
        const auto& tree = m.tree();
        uint32_t idx = tree.find_by_pid(static_cast<DWORD>(pid));
        if (idx == INVALID_IDX) return {};
        const auto* entry = tree.try_at(idx);
        if (!entry || !entry->alive) return {};
        return process_entry_to_json(tree, m.rules(), idx, true);
    });
    if (result.is_null() || result.empty()) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    const auto tree_psn = result["psn"].get<std::uint64_t>();
    if (psn && *psn != tree_psn) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    // OS calls run outside the strand.
    auto os = query_process_detail_impl(static_cast<DWORD>(pid), tree_psn);
    if (!os.same_process) {
        throw api_exception{api_error::not_found, "Process not found"};
    }
    result["image_path"] = std::move(os.image_path);
    result["cmdline"]    = std::move(os.cmdline);
    return result;
}

nlohmann::json process_tree_service::list_hijacked() const {
    return exec_.query([](const domain::process_tree_manager& m) -> nlohmann::json {
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
