// v0.14 #8: icon cache bookkeeping (LRU cap + negative entries with backoff).
#include "common/bounded_backoff_cache.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace std::chrono_literals;

struct fake_clock {
    using duration = std::chrono::milliseconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<fake_clock>;
    static constexpr bool is_steady = true;
};
using cache = clew::bounded_backoff_cache<std::string, fake_clock>;
using st = cache::state;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error(#expr); } while (false)

static fake_clock::time_point at(long ms) { return fake_clock::time_point{fake_clock::duration{ms}}; }

static void hit_and_miss() {
    cache c(4);
    CHECK(c.lookup("a", at(0)).s == st::miss);
    c.put("a", "C:\\a.exe");
    auto r = c.lookup("a", at(0));
    CHECK(r.s == st::hit); CHECK(*r.value == "C:\\a.exe");
}

static void failures_back_off_exponentially_and_cap() {
    cache c(4, 5s, 20s);
    CHECK(c.put_failure("x", at(0)) == 5s);
    CHECK(c.lookup("x", at(4'999)).s == st::negative);
    CHECK(c.lookup("x", at(5'000)).s == st::miss);   // retry allowed
    CHECK(c.put_failure("x", at(5'000)) == 10s);
    CHECK(c.lookup("x", at(14'999)).s == st::negative);
    CHECK(c.put_failure("x", at(15'000)) == 20s);
    CHECK(c.put_failure("x", at(35'000)) == 20s);    // capped
    c.put("x", "found");                             // success resets
    CHECK(c.lookup("x", at(35'001)).s == st::hit);
    CHECK(c.put_failure("x", at(40'000)) == 5s);
}

static void lru_eviction_keeps_recent_entries() {
    cache c(3);
    c.put("a", "1"); c.put("b", "2"); c.put("c", "3");
    CHECK(c.lookup("a", at(0)).s == st::hit);        // a is now most recent
    c.put_failure("d", at(0));                       // negative entries count too
    CHECK(c.size() == 3);
    CHECK(c.lookup("b", at(0)).s == st::miss);       // b was least recent
    CHECK(c.lookup("a", at(0)).s == st::hit);
    CHECK(c.lookup("c", at(0)).s == st::hit);
    CHECK(c.lookup("d", at(0)).s == st::negative);
    for (int i = 0; i < 100; ++i) c.put("k" + std::to_string(i), "v");
    CHECK(c.size() == 3);
}

static void overwrite_does_not_duplicate() {
    cache c(2);
    c.put("a", "1"); c.put("a", "2"); c.put_failure("a", at(0)); c.put("a", "3");
    CHECK(c.size() == 1);
    CHECK(*c.lookup("a", at(0)).value == "3");
}

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"hit and miss", hit_and_miss},
        {"failures back off exponentially and cap", failures_back_off_exponentially_and_cap},
        {"LRU eviction keeps recent entries", lru_eviction_keeps_recent_entries},
        {"overwrite does not duplicate", overwrite_does_not_duplicate},
    };
    int failures = 0;
    for (const auto& [name, test] : cases) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { ++failures; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    return failures ? 1 : 0;
}
