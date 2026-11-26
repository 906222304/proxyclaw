#pragma once

// process_tree_service — process tree queries + hijack/unhijack CRUD.
//
// The full-tree snapshot path (formerly served via /api/processes) was
// removed when the backend->frontend push channel switched from SSE to
// WebView2 PostMessage; the snapshot is now delivered straight inside
// each push payload by process_projection. Per-PID query and hijack
// CRUD remain HTTP.

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "domain/strand_bound.hpp"
#include "hook/hook_status.hpp"
#include "process/process_info_cache.hpp"

namespace clew {

class process_tree_service {
public:
    explicit process_tree_service(strand_bound_manager& exec,
                                  process_info_cache* info_cache = nullptr);

    process_tree_service(const process_tree_service&)            = delete;
    process_tree_service& operator=(const process_tree_service&) = delete;

    void set_hook_status_provider(hook::status_provider provider) {
        hook_status_provider_ = std::move(provider);
    }

    // /api/processes/:pid
    [[nodiscard]] nlohmann::json find_process(std::uint32_t pid) const;
    // /api/processes/:pid/detail[?psn=N] — adds cmdline + image_path
    // (queried off-strand). With `psn`, answers 404 unless the tree's entry
    // for `pid` is that process; either way the OS facts are read only from
    // a handle whose PSN matches the tree entry, so a reused PID never lends
    // the new process's path / command line to the old entry.
    [[nodiscard]] nlohmann::json find_process_detail(std::uint32_t pid,
                                                     std::optional<std::uint64_t> psn = {}) const;

    // /api/hijack
    [[nodiscard]] nlohmann::json list_hijacked() const;

    // /api/hijack/:pid — POST and DELETE variants
    void hijack(std::uint32_t pid, bool tree_mode, std::uint32_t group_id);
    void unhijack(std::uint32_t pid, bool tree_mode);

    // /api/hijack/batch — action = "hijack" | "unhijack"
    nlohmann::json batch_hijack(const std::vector<std::uint32_t>& pids,
                                std::string_view action,
                                std::uint32_t group_id);

private:
    strand_bound_manager& exec_;
    process_info_cache*   info_cache_{nullptr};
    hook::status_provider hook_status_provider_;
};

} // namespace clew
