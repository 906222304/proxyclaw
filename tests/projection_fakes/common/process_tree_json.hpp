#pragma once
#include "domain/process_tree_manager.hpp"
#include "hook/hook_status.hpp"
namespace clew {
inline std::string process_tree_to_json_string(
    const domain::fake_tree& tree, int, const hook::status_map* = nullptr) {
    ++tree.serializations;
    return tree.json;
}
}
