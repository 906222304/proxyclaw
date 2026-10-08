#pragma once
#include <string>
namespace clew::domain {
struct fake_tree {
    std::string json = "[]";
    mutable unsigned serializations = 0;
    unsigned alive_count() const { return 1; }
};
class process_tree_manager {
    fake_tree tree_;
public:
    fake_tree& tree() { return tree_; }
    int rules() const { return 0; }
};
}
