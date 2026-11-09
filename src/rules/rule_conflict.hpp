#pragma once

// rule_conflict: more than one source claims the same process (ROADMAP v0.14 #4).
//
// Auto rules are evaluated in config order and the FIRST rule whose process
// match (name + cmdline + image path, or process-tree inheritance) succeeds
// decides the process: its proxy group, protocol and destination filter
// apply. Later rules that also match are shadowed; they never apply to that
// process, not even for destinations the winner's filter sends direct.
// A manual hijack beats every auto rule, so all matching rules are shadowed.
//
// Std-only so the connection projection (projection/connection_rows) can use
// it without pulling in the Windows-bound rule engine.

#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace clew {

struct rule_conflict {
    bool                     manual{false};  // the winner is a manual hijack
    std::string              winner;         // winning rule id ("" when manual)
    std::vector<std::string> shadowed;       // shadowed rule ids, config order

    [[nodiscard]] bool empty() const noexcept { return shadowed.empty(); }
};

// Conflict for one process from the ids of every enabled rule that matches
// it, in config order. No conflict (empty result) when a single rule matches
// and there is no manual hijack, or when nothing matches.
[[nodiscard]] inline rule_conflict make_rule_conflict(bool manual,
                                                      std::vector<std::string> matching) {
    rule_conflict c;
    if (manual) {
        c.manual   = !matching.empty();
        c.shadowed = std::move(matching);
        return c;
    }
    if (matching.size() < 2) return c;
    c.winner = std::move(matching.front());
    c.shadowed.assign(std::make_move_iterator(matching.begin() + 1),
                      std::make_move_iterator(matching.end()));
    return c;
}

} // namespace clew
