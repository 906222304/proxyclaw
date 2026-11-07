#pragma once

// orphan_registry — children whose parent the tree does not know yet.
//
// A process can reach the tree before its parent: ETW delivers rundown
// events in no particular order, a sync-resolve inserts a chain whose top
// parent has no tree entry yet, and an EventsLost burst can drop a parent's
// START altogether. Such a child is inserted as a root and parked here under
// its parent's PSN; when the parent arrives it is attached.
//
// Children are identified by (pid, psn), never by flat_tree index:
// flat_tree::compact() renumbers every entry, so an index kept across a
// compaction would point at an unrelated process and re-parent it (wrong
// tree-rule inheritance, wrong UI tree). The index is resolved when the
// parent arrives, through find_by_pid_psn, which also rejects a recycled PID.
//
// Bounded: entries older than the expiry are dropped by expire() (the child
// simply stays a root, which it already is), and park() refuses new entries
// past the cap. Strand-only, like flat_tree.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <unordered_map>
#include <vector>

#include "process/flat_tree.hpp"

namespace clew::domain {

class orphan_registry {
public:
    using clock = std::chrono::steady_clock;

    static constexpr std::size_t kDefaultCap = 4096;

    explicit orphan_registry(std::size_t cap = kDefaultCap) : cap_(cap) {}

    // Park child (pid, psn) until a process with parent_psn arrives. False
    // when the registry is full; the child then just stays a root.
    bool park(uint64_t parent_psn, DWORD pid, uint64_t psn, clock::time_point now) {
        if (size_ >= cap_) {
            ++dropped_;
            return false;
        }
        by_parent_psn_[parent_psn].push_back(waiting{pid, psn, now});
        ++size_;
        return true;
    }

    // The parent with `parent_psn` is now at parent_idx: attach every waiting
    // child that is still the same live process. Returns how many attached.
    std::size_t drain(flat_tree& tree, uint64_t parent_psn, uint32_t parent_idx) {
        auto it = by_parent_psn_.find(parent_psn);
        if (it == by_parent_psn_.end()) return 0;
        std::size_t attached = 0;
        for (const auto& w : it->second) {
            const uint32_t child_idx = tree.find_by_pid_psn(w.pid, w.psn);
            if (child_idx == INVALID_IDX || child_idx == parent_idx) continue;
            if (!tree.at(child_idx).alive) continue;
            tree.attach_child(parent_idx, child_idx);
            ++attached;
        }
        size_ -= it->second.size();
        by_parent_psn_.erase(it);
        return attached;
    }

    // Forget entries parked at or before `cutoff` (or all of them with
    // clock::time_point::max()). Their children already are roots; forgetting
    // only means a parent arriving later no longer adopts them. Returns how
    // many of the forgotten children were still alive.
    std::size_t expire(const flat_tree& tree, clock::time_point cutoff) {
        std::size_t live = 0;
        for (auto it = by_parent_psn_.begin(); it != by_parent_psn_.end();) {
            auto& v = it->second;
            const auto before = v.size();
            std::erase_if(v, [&](const waiting& w) {
                if (w.since > cutoff) return false;
                const uint32_t idx = tree.find_by_pid_psn(w.pid, w.psn);
                if (idx != INVALID_IDX && tree.at(idx).alive) ++live;
                return true;
            });
            size_ -= before - v.size();
            it = v.empty() ? by_parent_psn_.erase(it) : std::next(it);
        }
        return live;
    }

    std::size_t expire_all(const flat_tree& tree) {
        return expire(tree, clock::time_point::max());
    }

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] std::size_t dropped() const noexcept { return dropped_; }
    [[nodiscard]] std::size_t cap() const noexcept { return cap_; }

private:
    struct waiting {
        DWORD             pid;
        uint64_t          psn;
        clock::time_point since;
    };

    std::unordered_map<uint64_t, std::vector<waiting>> by_parent_psn_;
    std::size_t size_{0};
    std::size_t dropped_{0};
    std::size_t cap_;
};

} // namespace clew::domain
