#pragma once

// Bounded thread-safe (pid, psn)-keyed process metadata cache (v0.18 #3).
//
// Shared across rule_engine_v3 (strand) and process_tree_service (HTTP worker
// threads) so image_path, cmdline, and Store PackageFamilyName are queried from
// the OS at most once per live process identity instead of opening multiple
// handles or repeating NtQueryInformationProcess on every UI detail request.
//
// Pure C++23 (no Windows headers) so it is directly unit tested.
//
// Safety invariant: callers MUST still verify the live PSN against the expected
// PSN on every cache hit in off-strand paths (e.g. /api/processes/:pid/detail)
// so a recycled PID before ETW STOP never serves stale metadata.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace clew {

enum process_info_fields : uint8_t {
    kFieldNone          = 0,
    kFieldImagePath     = 1u << 0,
    kFieldCmdline       = 1u << 1,
    kFieldPackageFamily = 1u << 2,
    kFieldAll           = kFieldImagePath | kFieldCmdline | kFieldPackageFamily,
};

struct process_info_key {
    uint32_t pid{0};
    uint64_t psn{0};

    bool operator==(const process_info_key&) const noexcept = default;
};

struct process_info_key_hash {
    std::size_t operator()(const process_info_key& k) const noexcept {
        uint64_t h = (static_cast<uint64_t>(k.pid) * 0x9E3779B97F4A7C15ull) ^
                     (k.psn * 0xBF58476D1CE4E5B9ull);
        h ^= (h >> 30);
        h *= 0x94D049BB133111EBull;
        return static_cast<std::size_t>(h ^ (h >> 31));
    }
};

struct process_info_value {
    std::string image_path;
    std::string cmdline;
    std::string package_family_name;
    uint8_t     queried_mask{kFieldNone};

    bool has(uint8_t mask) const noexcept {
        return (queried_mask & mask) == mask;
    }
};

class process_info_cache {
public:
    static constexpr std::size_t kDefaultCapacity = 4096;

    struct Stats {
        std::size_t entries{0};
        std::size_t capacity{0};
        std::size_t peak{0};
        uint64_t    hits{0};
        uint64_t    misses{0};
        uint64_t    psn_mismatches{0};
        uint64_t    evictions{0};
        uint64_t    erased_on_exit{0};
    };

    explicit process_info_cache(std::size_t capacity = kDefaultCapacity)
        : capacity_(capacity) {}

    process_info_cache(const process_info_cache&)            = delete;
    process_info_cache& operator=(const process_info_cache&) = delete;

    // Returns a copy when (pid, psn) is cached and covers all bits in
    // `required_mask`. Updates LRU recency on hit.
    [[nodiscard]] std::optional<process_info_value> get(uint32_t pid, uint64_t psn,
                                                        uint8_t required_mask = kFieldAll) {
        std::lock_guard lk(mu_);
        const auto it = map_.find(process_info_key{pid, psn});
        if (it == map_.end() || !it->second->second.has(required_mask)) {
            ++misses_;
            return std::nullopt;
        }
        lru_.splice(lru_.begin(), lru_, it->second);
        ++hits_;
        return it->second->second;
    }

    // Insert or merge queried fields for (pid, psn). Evicts the least recently
    // used entry when at capacity.
    void put(uint32_t pid, uint64_t psn, process_info_value val) {
        if (capacity_ == 0 || val.queried_mask == kFieldNone) return;
        std::lock_guard lk(mu_);
        const process_info_key key{pid, psn};
        if (auto it = map_.find(key); it != map_.end()) {
            auto& dst = it->second->second;
            if (val.has(kFieldImagePath))     dst.image_path = std::move(val.image_path);
            if (val.has(kFieldCmdline))       dst.cmdline = std::move(val.cmdline);
            if (val.has(kFieldPackageFamily)) dst.package_family_name = std::move(val.package_family_name);
            dst.queried_mask |= val.queried_mask;
            lru_.splice(lru_.begin(), lru_, it->second);
            return;
        }
        while (map_.size() >= capacity_) {
            const auto victim_key = lru_.back().first;
            lru_.pop_back();
            map_.erase(victim_key);
            ++evictions_;
        }
        lru_.emplace_front(key, std::move(val));
        map_.emplace(key, lru_.begin());
        peak_ = std::max(peak_, map_.size());
    }

    // Convenience helper for sync-resolve, which already fetches the full image
    // path while identifying the process.
    void seed_image_path(uint32_t pid, uint64_t psn, std::string image_path) {
        if (image_path.empty()) return;
        process_info_value v;
        v.image_path = std::move(image_path);
        v.queried_mask = kFieldImagePath;
        put(pid, psn, std::move(v));
    }

    // Called on ETW STOP, PID reuse tombstone, or live PSN mismatch.
    bool erase(uint32_t pid, uint64_t psn) {
        std::lock_guard lk(mu_);
        const auto it = map_.find(process_info_key{pid, psn});
        if (it == map_.end()) return false;
        lru_.erase(it->second);
        map_.erase(it);
        ++erased_on_exit_;
        return true;
    }

    void record_psn_mismatch() {
        std::lock_guard lk(mu_);
        ++psn_mismatches_;
    }

    void clear() {
        std::lock_guard lk(mu_);
        map_.clear();
        lru_.clear();
    }

    [[nodiscard]] Stats stats() const {
        std::lock_guard lk(mu_);
        return {
            .entries        = map_.size(),
            .capacity       = capacity_,
            .peak           = peak_,
            .hits           = hits_,
            .misses         = misses_,
            .psn_mismatches = psn_mismatches_,
            .evictions      = evictions_,
            .erased_on_exit = erased_on_exit_,
        };
    }

private:
    using list_t = std::list<std::pair<process_info_key, process_info_value>>;

    std::size_t capacity_;
    mutable std::mutex mu_;
    list_t lru_;
    std::unordered_map<process_info_key, list_t::iterator, process_info_key_hash> map_;
    std::size_t peak_{0};
    uint64_t hits_{0};
    uint64_t misses_{0};
    uint64_t psn_mismatches_{0};
    uint64_t evictions_{0};
    uint64_t erased_on_exit_{0};
};

} // namespace clew
