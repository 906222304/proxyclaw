#pragma once

// bounded_backoff_cache — string-keyed LRU cache that also remembers misses.
//
// Used by icon_cache for both maps (full path -> PNG, exe name -> path):
//   - capacity: least recently used entries are evicted past `capacity`
//     (hits and negative entries count alike), so the cache cannot grow
//     without bound across a long session of short-lived processes.
//   - negative entries: a failed lookup is remembered and answered as
//     `negative` until its retry time, then the caller may try again. The
//     delay doubles per consecutive failure (base, 2*base, ... max), so an
//     exe that never resolves is not looked up on every request, and one
//     that becomes resolvable later is picked up again.
//
// Not thread-safe: the owner serializes access. Pure, no Windows headers;
// unit tested in tests/test_icon_store.cpp.

#include <chrono>
#include <cstddef>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "core/string_hash.hpp"

namespace clew {

template <class V, class Clock = std::chrono::steady_clock>
class bounded_backoff_cache {
public:
    using time_point = typename Clock::time_point;
    using duration   = typename Clock::duration;

    enum class state { miss, hit, negative };

    struct result {
        state s = state::miss;
        const V* value = nullptr;  // hit only; valid until the next mutation
    };

    explicit bounded_backoff_cache(std::size_t capacity,
                                   duration base_backoff = std::chrono::seconds(5),
                                   duration max_backoff  = std::chrono::minutes(10))
        : capacity_(capacity ? capacity : 1), base_(base_backoff), max_(max_backoff) {}

    result lookup(std::string_view key, time_point now) {
        auto it = map_.find(key);
        if (it == map_.end()) return {};
        touch(it->second);
        auto& e = it->second;
        if (e.value) return {state::hit, &*e.value};
        if (now < e.retry_at) return {state::negative, nullptr};
        return {};  // backoff elapsed: caller retries (failure count kept)
    }

    const V& put(std::string_view key, V value) {
        auto& e = slot(key);
        e.value = std::move(value);
        e.failures = 0;
        evict();
        return *e.value;
    }

    // Records a failed lookup; returns the delay until the next retry.
    duration put_failure(std::string_view key, time_point now) {
        auto& e = slot(key);
        e.value.reset();
        if (e.failures < 30) ++e.failures;
        duration d = base_;
        for (int i = 1; i < e.failures && d < max_; ++i) d *= 2;
        if (d > max_) d = max_;
        e.retry_at = now + d;
        evict();
        return d;
    }

    [[nodiscard]] std::size_t size() const noexcept { return map_.size(); }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

private:
    struct entry {
        std::optional<V> value;          // empty = negative entry
        time_point retry_at{};
        int failures = 0;
        std::list<std::string>::iterator lru;
    };

    entry& slot(std::string_view key) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            touch(it->second);
            return it->second;
        }
        lru_.emplace_front(key);
        auto [ins, _] = map_.try_emplace(std::string(key));
        ins->second.lru = lru_.begin();
        return ins->second;
    }

    void touch(entry& e) { lru_.splice(lru_.begin(), lru_, e.lru); }

    void evict() {
        while (map_.size() > capacity_) {
            map_.erase(map_.find(std::string_view{lru_.back()}));
            lru_.pop_back();
        }
    }

    std::size_t capacity_;
    duration base_, max_;
    std::list<std::string> lru_;  // front = most recently used
    string_map<entry> map_;
};

} // namespace clew
