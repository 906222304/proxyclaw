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
#include <set>
#include <utility>
#include <vector>

namespace clew::hook {

class inject_tracker {
public:
    using key = std::pair<uint32_t, uint64_t>;   // (pid, psn)

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

    // Called on the strand when decide_child() approves import-table injection:
    // stamp with gen_ + 1 so any in-flight sweep (gen <= gen_) won't prune it
    // before the next sweep sees the child in the tree.
    void mark_child(const key& k) {
        done_[k] = entry{gen_ + 1, /*from_child=*/true};
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
    void mark_swept(const key& k, uint64_t gen) {
        done_[k] = entry{gen, /*from_child=*/false};
    }

    // Called by the injector thread at the end of sweep `gen`: forget entries
    // absent from `live` whose generation is <= `gen`.
    void prune(const std::set<key>& live, uint64_t gen) {
        for (auto it = done_.begin(); it != done_.end();) {
            if (!live.contains(it->first) && it->second.gen <= gen)
                it = done_.erase(it);
            else
                ++it;
        }
    }

    std::size_t done_count() const noexcept { return done_.size(); }

private:
    struct entry {
        uint64_t gen{0};
        bool from_child{false};
    };

    uint64_t gen_{0};
    std::vector<key> wanted_;
    bool dirty_{false};
    std::map<key, entry> done_;
};

} // namespace clew::hook
