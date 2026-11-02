// UDP first-packet parking bookkeeping (src/udp/udp_first_packet.hpp).
// No driver, no admin rights.

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "udp/udp_first_packet.hpp"

using namespace clew;
using namespace std::chrono_literals;
using clock_type = std::chrono::steady_clock;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

const auto undecided = [] { return true; };

void parks_until_decision_in_order() {
    udp_first_packet_parker<int> p;
    const auto t0 = clock_type::now();
    for (int i = 1; i <= 3; ++i) {
        int v = i;
        check(p.park(5000, v, t0, undecided) == udp_park_result::parked, "park " + std::to_string(i));
    }
    int other = 9;
    p.park(6000, other, t0, undecided);
    check(p.size() == 4, "four parked");
    auto got = p.take(5000);
    check(got == std::vector<int>{1, 2, 3}, "take returns arrival order");
    check(p.size() == 1, "other port still parked");
    check(p.take(5000).empty(), "second take is empty");
}

void decided_under_lock_is_not_parked() {
    udp_first_packet_parker<int> p;
    int v = 1;
    auto r = p.park(5000, v, clock_type::now(), [] { return false; });
    check(r == udp_park_result::decided, "decided port not parked");
    check(p.size() == 0, "nothing held");
}

void limits() {
    udp_first_packet_parker<int> p(UdpParkingLimits{3, 2});
    const auto t0 = clock_type::now();
    int a = 1, b = 2, c = 3, d = 4, e = 5;
    check(p.park(1, a, t0, undecided) == udp_park_result::parked, "1st");
    check(p.park(1, b, t0, undecided) == udp_park_result::parked, "2nd");
    check(p.park(1, c, t0, undecided) == udp_park_result::full, "per-port limit");
    check(p.park(2, d, t0, undecided) == udp_park_result::parked, "other port");
    check(p.park(3, e, t0, undecided) == udp_park_result::full, "total limit");
    check(p.size() == 3, "three held");
    check(p.take(3).empty(), "full port left no empty entry");
}

void watchdog_expiry() {
    udp_first_packet_parker<int> p;
    const auto t0 = clock_type::now();
    int a = 1, b = 2, c = 3;
    p.park(10, a, t0, undecided);
    p.park(10, b, t0 + 15ms, undecided);   // same port: deadline counts from the oldest
    p.park(11, c, t0 + 15ms, undecided);
    auto due = p.expire(t0 + 19ms, 20ms);
    check(due.empty(), "nothing due before the deadline");
    due = p.expire(t0 + 20ms, 20ms);
    check(due.size() == 1 && due[0].first == 10 && due[0].second == std::vector<int>{1, 2},
          "oldest port expires with all its packets");
    due = p.expire(t0 + 35ms, 20ms);
    check(due.size() == 1 && due[0].first == 11, "second port expires later");
    check(p.size() == 0, "all released");
    int d = 4;
    p.park(10, d, t0 + 40ms, undecided);
    check(p.expire(t0 + 50ms, 20ms).empty(), "re-parked port gets a fresh deadline");
}

// The publisher stores its decision, then takes; a worker parks only if the
// decision is still absent under the lock. No packet may be stranded.
void no_packet_stranded_by_race() {
    for (int round = 0; round < 200; ++round) {
        udp_first_packet_parker<int> p;
        std::atomic<bool> decided{false};
        std::atomic<int> handled_now{0};
        std::atomic<int> released{0};
        std::thread worker([&] {
            for (int i = 0; i < 50; ++i) {
                int v = i;
                auto r = p.park(7, v, clock_type::now(), [&] { return !decided.load(); });
                if (r == udp_park_result::decided) handled_now++;
            }
        });
        std::thread publisher([&] {
            std::this_thread::yield();
            decided.store(true);
            released += static_cast<int>(p.take(7).size());
        });
        worker.join();
        publisher.join();
        const int stranded = static_cast<int>(p.size());
        check(stranded == 0, "round " + std::to_string(round) + ": " + std::to_string(stranded) +
                                 " packets stranded after the decision");
        check(handled_now + released == 50, "every packet handled once");
        if (failures) return;
    }
}

} // namespace

int main() {
    parks_until_decision_in_order();
    decided_under_lock_is_not_parked();
    limits();
    watchdog_expiry();
    no_packet_stranded_by_race();
    if (failures) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "udp_first_packet_tests: all passed\n";
    return 0;
}
