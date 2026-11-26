#pragma once

// Hook mode: tracks which live (pid, psn) processes have already been
// injected (or skipped/failed) across periodic 1 s sweeps and synchronous
// child-creation notifications from the DLL.
//
// Each sweep advances a monotonic generation counter. A child marked by
// mark_child() between sweep G and sweep G+1 is stamped with G+1 so that
// sweep G finishing concurrently on the injector thread cannot prune it
// before sweep G+1 sees the child in the process tree.

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "hook/hook_status.hpp"

namespace clew::hook {

class inject_tracker {
public:
    using key = process_key;   // (pid, psn)

    struct sweep_batch {
        std::vector<key> wanted;
        uint64_t gen{0};
    };

    // Called on the strand each sweep: advances generation and publishes
    // the live proxied set.
    uint64_t publish_wanted(std::vector<key> wanted) {
        wanted_ = std::move(wanted);
        dirty_ = true;
        return ++gen_;
    }

    bool dirty() const noexcept { return dirty_; }

    // Called by the injector thread when it wakes up.
    sweep_batch take_wanted() {
        dirty_ = false;
        return {wanted_, gen_};
    }

    bool is_done(const key& k) const { return done_.contains(k); }

    std::optional<inject_status> status_of(const key& k) const {
        const auto it = done_.find(k);
        if (it == done_.end()) return std::nullopt;
        return it->second.status;
    }

    status_map snapshot_statuses() const {
        status_map out;
        for (const auto& [k, e] : done_) out.emplace(k, e.status);
        return out;
    }

    status_counts count_statuses() const noexcept {
        status_counts c;
        for (const auto& [_, e] : done_) {
            switch (e.status) {
            case inject_status::injected:    ++c.injected;    break;
            case inject_status::wow64:       ++c.wow64;       break;
            case inject_status::restricted:  ++c.restricted;  break;
            case inject_status::signed_only: ++c.signed_only; break;
            case inject_status::open_failed: ++c.open_failed; break;
            case inject_status::failed:      ++c.failed;      break;
            case inject_status::pending:     break;
            }
        }
        return c;
    }

    // Called on the strand when decide_child() approves import-table injection:
    // stamp with gen_ + 1 so any in-flight sweep (gen <= gen_) won't prune it
    // before the next sweep sees the child in the tree.
    void mark_child(const key& k) {
        done_[k] = entry{gen_ + 1, /*from_child=*/true, inject_status::injected};
    }

    // Called on the strand if DetourUpdateProcessWithDll fails in the parent:
    // remove only if it was marked via mark_child() so a stale/rogue message
    // cannot clear an already-injected process or underflow counters.
    bool clear_child(const key& k) {
        const auto it = done_.find(k);
        if (it == done_.end() || !it->second.from_child) return false;
        done_.erase(it);
        return true;
    }

    // Called by the injector thread after inject_into() finishes for sweep `gen`.
    void mark_swept(const key& k, uint64_t gen, inject_status status = inject_status::injected) {
        done_[k] = entry{gen, /*from_child=*/false, status};
    }

    // Called by the injector thread at the end of sweep `gen`: forget entries
    // absent from `live` whose generation is <= `gen`. Returns true if any
    // entry was pruned.
    bool prune(const std::set<key>& live, uint64_t gen) {
        bool removed = false;
        for (auto it = done_.begin(); it != done_.end();) {
            if (!live.contains(it->first) && it->second.gen <= gen) {
                it = done_.erase(it);
                removed = true;
            } else {
                ++it;
            }
        }
        return removed;
    }

    std::size_t done_count() const noexcept { return done_.size(); }

private:
    struct entry {
        uint64_t gen{0};
        bool from_child{false};
        inject_status status{inject_status::injected};
    };

    uint64_t gen_{0};
    std::vector<key> wanted_;
    bool dirty_{false};
    std::map<key, entry> done_;
};

} // namespace clew::hook
