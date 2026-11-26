// Unit tests for v0.18 #3 bounded (pid, psn)-keyed process_info_cache.
// Pure C++23, no driver / admin rights required.

#include <atomic>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "process/process_info_cache.hpp"

using namespace clew;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

void keyed_by_pid_and_psn_no_reuse_collision() {
    process_info_cache cache(16);
    process_info_value old_proc{
        .image_path = "C:\\Apps\\old.exe",
        .cmdline = "old.exe --old",
        .package_family_name = "",
        .queried_mask = kFieldAll,
    };
    process_info_value new_proc{
        .image_path = "C:\\Apps\\new.exe",
        .cmdline = "new.exe --new",
        .package_family_name = "Contoso.New_abc123",
        .queried_mask = kFieldAll,
    };

    cache.put(/*pid=*/4242, /*psn=*/100, old_proc);
    cache.put(/*pid=*/4242, /*psn=*/200, new_proc);

    const auto a = cache.get(4242, 100, kFieldAll);
    const auto b = cache.get(4242, 200, kFieldAll);
    const auto c = cache.get(4242, 300, kFieldAll);
    check(a && a->image_path == "C:\\Apps\\old.exe" && a->cmdline == "old.exe --old",
          "old (pid, psn) returns old metadata");
    check(b && b->image_path == "C:\\Apps\\new.exe" && b->package_family_name == "Contoso.New_abc123",
          "recycled PID with new PSN returns new metadata");
    check(!c.has_value(), "unknown PSN misses cleanly");

    // Erasing old PSN leaves new PSN intact.
    check(cache.erase(4242, 100), "erase old PSN succeeds");
    check(!cache.erase(4242, 100), "second erase is idempotent no-op");
    check(!cache.get(4242, 100, kFieldAll).has_value(), "erased entry gone");
    check(cache.get(4242, 200, kFieldAll).has_value(), "recycled PID's new PSN untouched");
}

void partial_seed_and_upgrade_merge() {
    process_info_cache cache(16);
    cache.seed_image_path(/*pid=*/1000, /*psn=*/7, "C:\\Program Files\\Git\\bin\\git.exe");

    // Image path request hits immediately without needing cmdline.
    const auto path_only = cache.get(1000, 7, kFieldImagePath);
    check(path_only && path_only->image_path == "C:\\Program Files\\Git\\bin\\git.exe",
          "seeded image_path hits kFieldImagePath");

    // Full request misses until cmdline + pfn are populated.
    check(!cache.get(1000, 7, kFieldAll).has_value(), "seeded entry misses kFieldAll");
    check(!cache.get(1000, 7, kFieldCmdline).has_value(), "seeded entry misses kFieldCmdline");

    // Partial put merges cmdline without clobbering image_path.
    process_info_value cmd_only;
    cmd_only.cmdline = "git.exe push origin main";
    cmd_only.queried_mask = kFieldCmdline;
    cache.put(1000, 7, std::move(cmd_only));

    const auto both = cache.get(1000, 7, kFieldImagePath | kFieldCmdline);
    check(both && both->image_path == "C:\\Program Files\\Git\\bin\\git.exe" &&
          both->cmdline == "git.exe push origin main",
          "merge preserves previously seeded image_path while adding cmdline");
    check(cache.stats().entries == 1, "merge updates in place without duplicating");
}

void lru_eviction_and_counters() {
    process_info_cache cache(/*capacity=*/2);
    process_info_value v1{.image_path = "a.exe", .cmdline = "a", .package_family_name = "", .queried_mask = kFieldAll};
    process_info_value v2{.image_path = "b.exe", .cmdline = "b", .package_family_name = "", .queried_mask = kFieldAll};
    process_info_value v3{.image_path = "c.exe", .cmdline = "c", .package_family_name = "", .queried_mask = kFieldAll};

    cache.put(1, 10, v1);
    cache.put(2, 20, v2);
    // Touch (1, 10) so (2, 20) becomes least recently used.
    check(cache.get(1, 10, kFieldAll).has_value(), "touch (1, 10)");
    cache.put(3, 30, v3);

    check(cache.get(1, 10, kFieldAll).has_value(), "recently used (1, 10) kept");
    check(!cache.get(2, 20, kFieldAll).has_value(), "LRU (2, 20) evicted");
    check(cache.get(3, 30, kFieldAll).has_value(), "newest (3, 30) kept");

    cache.record_psn_mismatch();
    const auto s = cache.stats();
    check(s.entries == 2 && s.capacity == 2 && s.peak == 2, "size/capacity/peak exact");
    check(s.evictions == 1 && s.hits == 3 && s.misses == 1 && s.psn_mismatches == 1,
          "hit/miss/eviction/mismatch counters exact");
}

void concurrent_access_stays_bounded() {
    process_info_cache cache(/*capacity=*/64);
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t] {
            for (uint32_t i = 0; i < 500; ++i) {
                const uint32_t pid = static_cast<uint32_t>(t * 1000 + (i % 128));
                const uint64_t psn = static_cast<uint64_t>(i + 1);
                process_info_value v;
                v.image_path = "C:\\test.exe";
                v.cmdline = "test.exe";
                v.queried_mask = kFieldAll;
                cache.put(pid, psn, std::move(v));
                (void)cache.get(pid, psn, kFieldAll);
                if ((i & 3u) == 0u) cache.erase(pid, psn);
            }
        });
    }
    for (auto& th : threads) th.join();
    const auto s = cache.stats();
    check(s.entries <= 64 && s.peak <= 64, "concurrent cache never exceeds capacity");
    check(s.hits > 0 && s.erased_on_exit > 0, "concurrent hits and erasures recorded");
}

} // namespace

int main() {
    keyed_by_pid_and_psn_no_reuse_collision();
    partial_seed_and_upgrade_merge();
    lru_eviction_and_counters();
    concurrent_access_stays_bounded();
    if (failures) {
        std::cerr << "process_info_cache_tests: " << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "process_info_cache_tests: all passed\n";
    return 0;
}
