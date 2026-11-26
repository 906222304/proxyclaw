#pragma once

// Lock-free, fixed-memory microsecond latency histogram for hot paths
// (CONNECT -> decision publish, strand dispatch, SYN park wait).
//
// Zero allocations, zero locks, pure standard C++23 so it unit-tests cleanly
// on both Linux and Windows without platform headers.

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace clew {

// Overflow-safe QPC tick delta -> microseconds conversion.
inline constexpr uint64_t ticks_to_us(int64_t ticks, int64_t qpc_freq) noexcept {
    if (ticks <= 0 || qpc_freq <= 0) return 0;
    const auto t = static_cast<uint64_t>(ticks);
    const auto f = static_cast<uint64_t>(qpc_freq);
    return (t / f) * 1'000'000ULL + ((t % f) * 1'000'000ULL) / f;
}

struct latency_snapshot;

class latency_histogram {
public:
    // Fine resolution around the 20 ms SYN-parking watchdog:
    //   10 us steps up to 100 us
    //   50 us steps up to 500 us
    //  250 us steps up to 2 ms
    //    1 ms steps up to 10 ms
    //    5 ms steps up to 30 ms, then 40/50/100/250/500 ms + overflow bucket.
    static constexpr std::array<uint64_t, 41> kBoundsUs = {
        10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
        150, 200, 250, 300, 350, 400, 450, 500,
        750, 1000, 1250, 1500, 1750, 2000,
        3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000,
        15000, 20000, 25000, 30000, 40000, 50000,
        100000, 250000, 500000,
    };
    static constexpr std::size_t kBucketCount = kBoundsUs.size() + 1;

    latency_histogram() noexcept {
        for (auto& b : buckets_) b.store(0, std::memory_order_relaxed);
    }

    latency_histogram(const latency_histogram&)            = delete;
    latency_histogram& operator=(const latency_histogram&) = delete;

    static constexpr std::size_t bucket_index(uint64_t us) noexcept {
        const auto it = std::lower_bound(kBoundsUs.begin(), kBoundsUs.end(), us);
        return static_cast<std::size_t>(it - kBoundsUs.begin());
    }

    void record(uint64_t us) noexcept {
        buckets_[bucket_index(us)].fetch_add(1, std::memory_order_relaxed);
        sum_us_.fetch_add(us, std::memory_order_relaxed);
        uint64_t mx = max_us_.load(std::memory_order_relaxed);
        while (us > mx &&
               !max_us_.compare_exchange_weak(mx, us, std::memory_order_relaxed)) {}
    }

    latency_snapshot snapshot() const noexcept;

private:
    std::array<std::atomic<uint64_t>, kBucketCount> buckets_{};
    std::atomic<uint64_t> sum_us_{0};
    std::atomic<uint64_t> max_us_{0};
};

struct latency_snapshot {
    uint64_t count  = 0;
    uint64_t sum_us = 0;
    uint64_t max_us = 0;
    std::array<uint64_t, latency_histogram::kBucketCount> buckets{};

    uint64_t mean_us() const noexcept {
        return count ? (sum_us / count) : 0;
    }

    // Upper-bound quantile estimate for p in [0.0, 1.0].
    uint64_t quantile(double p) const noexcept {
        if (count == 0) return 0;
        const double clamped = p <= 0.0 ? 0.0 : (p >= 1.0 ? 1.0 : p);
        uint64_t rank = static_cast<uint64_t>(std::ceil(clamped * static_cast<double>(count)));
        if (rank == 0) rank = 1;
        if (rank > count) rank = count;

        uint64_t seen = 0;
        for (std::size_t i = 0; i < latency_histogram::kBoundsUs.size(); ++i) {
            seen += buckets[i];
            if (seen >= rank) {
                const uint64_t bound = latency_histogram::kBoundsUs[i];
                return (max_us > 0 && bound > max_us) ? max_us : bound;
            }
        }
        return max_us > 0 ? max_us : latency_histogram::kBoundsUs.back();
    }

    // Bucket-wise saturating delta between two cumulative snapshots (for
    // measuring a specific benchmark window without resetting global state).
    static latency_snapshot diff(const latency_snapshot& before,
                                 const latency_snapshot& after) noexcept {
        latency_snapshot out;
        for (std::size_t i = 0; i < out.buckets.size(); ++i) {
            out.buckets[i] = after.buckets[i] >= before.buckets[i]
                                 ? (after.buckets[i] - before.buckets[i])
                                 : 0;
            out.count += out.buckets[i];
        }
        out.sum_us = after.sum_us >= before.sum_us ? (after.sum_us - before.sum_us) : 0;
        out.max_us = 0;  // sub-window max is unknown from cumulative max_us alone
        return out;
    }
};

inline latency_snapshot latency_histogram::snapshot() const noexcept {
    latency_snapshot s;
    for (std::size_t i = 0; i < kBucketCount; ++i) {
        const uint64_t n = buckets_[i].load(std::memory_order_relaxed);
        s.buckets[i] = n;
        s.count += n;
    }
    s.sum_us = sum_us_.load(std::memory_order_relaxed);
    s.max_us = max_us_.load(std::memory_order_relaxed);
    return s;
}

} // namespace clew
