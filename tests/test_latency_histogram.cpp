// Unit tests for lock-free latency_histogram and ticks_to_us.
#include "core/latency_histogram.hpp"

#include <iostream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

using clew::latency_histogram;
using clew::latency_snapshot;
using clew::ticks_to_us;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error(#expr); } while (false)

static void empty_snapshot() {
    latency_histogram h;
    const auto s = h.snapshot();
    CHECK(s.count == 0);
    CHECK(s.sum_us == 0);
    CHECK(s.max_us == 0);
    CHECK(s.mean_us() == 0);
    CHECK(s.quantile(0.50) == 0);
    CHECK(s.quantile(0.95) == 0);
    CHECK(s.quantile(0.99) == 0);
}

static void ticks_conversion() {
    CHECK(ticks_to_us(0, 10'000'000) == 0);
    CHECK(ticks_to_us(-5, 10'000'000) == 0);
    CHECK(ticks_to_us(100, 0) == 0);
    CHECK(ticks_to_us(10, 10'000'000) == 1);
    CHECK(ticks_to_us(200'000, 10'000'000) == 20'000);
    // Large delta (~100 hours at 10 MHz) must not overflow uint64_t.
    const int64_t hundred_hours = 360'000LL * 10'000'000LL;
    CHECK(ticks_to_us(hundred_hours, 10'000'000) == 360'000'000'000ULL);
}

static void bucket_boundaries_and_quantiles() {
    latency_histogram h;
    // 90 fast samples at 15 us (bucket <= 20), 9 at 400 us (bucket <= 400),
    // 1 slow outlier at 22000 us (bucket <= 25000).
    for (int i = 0; i < 90; ++i) h.record(15);
    for (int i = 0; i < 9; ++i)  h.record(400);
    h.record(22000);

    const auto s = h.snapshot();
    CHECK(s.count == 100);
    CHECK(s.max_us == 22000);
    CHECK(s.mean_us() == (90 * 15 + 9 * 400 + 22000) / 100);
    CHECK(s.quantile(0.50) == 20);
    CHECK(s.quantile(0.90) == 20);
    CHECK(s.quantile(0.95) == 400);
    CHECK(s.quantile(0.99) == 400);
    CHECK(s.quantile(1.00) == 22000);  // capped by max_us (22000 < 25000)
}

static void overflow_and_small_cap() {
    latency_histogram small;
    small.record(3);
    small.record(5);
    const auto ss = small.snapshot();
    // All samples <= 5 us -> quantile capped by max_us (5) instead of 10.
    CHECK(ss.quantile(0.50) == 5);
    CHECK(ss.quantile(0.99) == 5);

    latency_histogram big;
    big.record(1'200'000);
    const auto bs = big.snapshot();
    CHECK(bs.buckets.back() == 1);
    CHECK(bs.quantile(0.99) == 1'200'000);
}

static void window_diff() {
    latency_histogram h;
    // Warmup noise: 50 very slow samples.
    for (int i = 0; i < 50; ++i) h.record(45000);
    const auto before = h.snapshot();

    // Measurement window: 100 fast samples at 25 us (<= 30) and 2 at 1800 us (<= 2000).
    for (int i = 0; i < 100; ++i) h.record(25);
    h.record(1800);
    h.record(1800);
    const auto after = h.snapshot();

    const auto delta = latency_snapshot::diff(before, after);
    CHECK(delta.count == 102);
    CHECK(delta.mean_us() == (100 * 25 + 3600) / 102);
    CHECK(delta.quantile(0.50) == 30);
    CHECK(delta.quantile(0.95) == 30);
    CHECK(delta.quantile(0.99) == 2000);
}

static void concurrent_records() {
    latency_histogram h;
    constexpr int kThreads = 4;
    constexpr int kPerThread = 2500;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&h, t] {
            for (int i = 0; i < kPerThread; ++i) {
                h.record(static_cast<uint64_t>((i + t) % 500));
            }
        });
    }
    for (auto& th : threads) th.join();

    const auto s = h.snapshot();
    CHECK(s.count == kThreads * kPerThread);
    CHECK(s.max_us == 499);
    CHECK(s.quantile(0.50) >= 200 && s.quantile(0.50) <= 300);
}

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"empty snapshot", empty_snapshot},
        {"ticks_to_us conversion and overflow safety", ticks_conversion},
        {"bucket boundaries and quantiles", bucket_boundaries_and_quantiles},
        {"overflow bucket and small max_us cap", overflow_and_small_cap},
        {"window diff isolates measurement phase", window_diff},
        {"concurrent lock-free recording", concurrent_records},
    };
    int failures = 0;
    for (const auto& [name, fn] : cases) {
        try {
            fn();
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& e) {
            ++failures;
            std::cerr << "FAIL " << name << ": " << e.what() << '\n';
        }
    }
    return failures ? 1 : 0;
}
