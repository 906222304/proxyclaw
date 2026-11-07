// v0.13.1 concurrency fixes: proxy group snapshot swap, debounced saves,
// config_store serialisation with unique temp files. Logging is replaced by
// network_fakes; nothing outside the test's own build directory is touched.
#include "common/debouncer.hpp"
#include "config/config_store.hpp"
#include "proxy/proxy_group_table.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

static void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
    std::cout << "PASS " << message << '\n';
}

static void group_table_swaps_whole_snapshots() {
    clew::proxy_group_table table;
    check(table.size() == 0 && !table.find(0), "empty table has no groups");

    // Writers publish maps where every entry of generation g has port == g;
    // a reader must never see two different generations in one snapshot
    // (the old in-place clear()+insert could expose half-built maps).
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> reads{0};
    std::atomic<bool> torn{false};
    std::vector<std::jthread> readers;
    for (int r = 0; r < 4; ++r) {
        readers.emplace_back([&] {
            while (!stop.load(std::memory_order_relaxed)) {
                const auto snap = table.load();
                if (!snap->empty()) {
                    const auto port = snap->begin()->second.port;
                    for (const auto& [id, g] : *snap) {
                        if (g.port != port || g.host != "h" + std::to_string(port)) torn = true;
                    }
                    if (snap->size() != 16) torn = true;
                }
                reads.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    std::vector<std::jthread> writers;
    for (int w = 0; w < 2; ++w) {
        writers.emplace_back([&, w] {
            for (uint16_t gen = 1; gen < 3000; ++gen) {
                const uint16_t port = static_cast<uint16_t>(gen * 2 + w);
                clew::ProxyGroupMap m;
                for (uint32_t id = 0; id < 16; ++id) m[id] = {"h" + std::to_string(port), port};
                table.publish(std::move(m));
            }
        });
    }
    writers.clear();  // join writers
    stop = true;
    readers.clear();
    check(!torn.load(), "readers only ever observe complete group snapshots");
    check(reads.load() > 0 && table.size() == 16, "concurrent publish/load completes");

    const auto held = table.load();
    table.publish({{7, {"new", 1080}}});
    check(held->size() == 16 && table.find(7)->port == 1080 && !table.find(0),
          "a held snapshot stays valid after a publish");
}

static void debouncer_coalesces_and_flushes() {
    std::atomic<int> runs{0};
    std::atomic<int> last{0};
    {
        clew::debouncer d{150ms};
        for (int i = 1; i <= 10; ++i) {
            d.schedule([&, i] { last = i; ++runs; });
            std::this_thread::sleep_for(5ms);
        }
        std::this_thread::sleep_for(700ms);
        check(runs == 1 && last == 10, "a burst of schedules runs only the last action once");

        d.schedule([&] { last = 99; ++runs; });
        check(d.has_pending(), "a new schedule is pending until the quiet period ends");
        d.flush();
        check(runs == 2 && last == 99 && !d.has_pending(), "flush runs the pending action now");

        d.schedule([&] { last = 123; ++runs; });
    }  // destructor flushes
    check(runs == 3 && last == 123, "destruction does not lose a pending action");
}

static std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>{f}, std::istreambuf_iterator<char>{}};
}

static void config_store_serialises_concurrent_writers() {
    const auto root = fs::current_path() / "build" / "concurrency-tests";
    fs::remove_all(root);
    fs::create_directories(root);
    const auto path = root / "proxyclaw.json";

    clew::config_manager mgr(path);
    check(mgr.load(), "fixture configuration created");
    clew::config_store store(mgr);
    std::atomic<int> notified{0};
    store.subscribe([&](const clew::ConfigV2&, clew::config_change) { ++notified; });

    // Geometry saves (as from the UI debouncer) racing API-style mutations.
    constexpr int per_thread = 40;
    std::vector<std::jthread> threads;
    threads.emplace_back([&] {
        for (int i = 0; i < per_thread; ++i) {
            store.mutate([i](clew::ConfigV2& c) {
                c.ui.window_x = i; c.ui.window_y = i; c.ui.window_width = 1000 + i; c.ui.window_height = 700 + i;
            }, clew::config_change::ui_geometry);
        }
    });
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < per_thread; ++i) {
                store.mutate([t, i](clew::ConfigV2& c) {
                    c.log_level = (i + t) % 2 ? "debug" : "info";
                    c.dns.upstream_host = "10.0.0." + std::to_string(t);
                }, clew::config_change::wholesale_replaced);
            }
        });
    }
    threads.clear();

    check(notified == 4 * per_thread, "every mutation notified observers");
    const auto on_disk = nlohmann::json::parse(read_file(path)).get<clew::ConfigV2>();
    const auto live = store.get();
    check(on_disk.ui.window_x == per_thread - 1 && on_disk.ui.window_width == 1000 + per_thread - 1,
          "the last geometry save is on disk");
    check(nlohmann::json(on_disk).dump() == nlohmann::json(live).dump(),
          "file on disk equals the in-memory configuration");
    int leftovers = 0;
    for (const auto& e : fs::directory_iterator(root)) {
        if (e.path().extension() == ".tmp") ++leftovers;
    }
    check(leftovers == 0, "no temporary files are left behind");
}

int main() {
    try {
        group_table_swaps_whole_snapshots();
        debouncer_coalesces_and_flushes();
        config_store_serialises_concurrent_writers();
        std::cout << "concurrency primitives: all passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
