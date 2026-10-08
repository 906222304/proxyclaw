#pragma once
#include "domain/process_tree_manager.hpp"
namespace clew {
inline std::string process_tree_to_json_string(const domain::fake_tree& tree, int) {
    ++tree.serializations;
    return tree.json;
}
}
