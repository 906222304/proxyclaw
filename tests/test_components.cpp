// ProxyClaw Component Integration Tests
// =====================================
// Tests core data structures and logic without admin/drivers.
//
// Build (VS2022 dev prompt):
//   cl /EHsc /std:c++latest /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DNOMINMAX ^
//      /I../src /I../WinDivert-2.2.2-A/include /I"%VCPKG_ROOT%/installed/x64-windows/include" ^
//      test_components.cpp ^
//      /link /LIBPATH:"%VCPKG_ROOT%/installed/x64-windows/lib" /LIBPATH:../WinDivert-2.2.2-A/x64 ^
//            ws2_32.lib WinDivert.lib
//
// WinDivert is needed only for the syn_parker pool tests (header types); no
// driver or admin rights are involved.
//
// /std:c++23 isn't recognized by VS2022 14.44 — use /std:c++latest.
// /DNOMINMAX — quill/std::numeric_limits collides with windows.h max() macro.
// /utf-8 — file contains UTF-8 (CN comments); cp 936 default mis-parses.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <cstddef>
#include <atomic>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <cassert>
#include <functional>
#include <future>
#include <sstream>
#include <thread>

#include "core/log.hpp"

// Components under test
#include "config/types.hpp"
#include "process/flat_tree.hpp"
#include "rules/rule_engine_v3.hpp"
#include "rules/traffic_filter.hpp"
#include "rules/policy_table.hpp"
#include "core/port_tracker.hpp"
#include "core/syn_parker.hpp"
#include "core/system_dns.hpp"
#include "udp/udp_port_tracker.hpp"
#include "udp/socks5_udp_session.hpp"

// ============================================================
// Minimal test framework
// ============================================================

static int g_pass = 0;
static int g_fail = 0;
static std::vector<std::string> g_errors;

class ScopedTestDirectory {
public:
    explicit ScopedTestDirectory(std::string_view label) {
        static std::atomic_uint64_t sequence{0};
        path_ = std::filesystem::current_path() /
                (".clew-test-" + std::string(label) + "-" +
                 std::to_string(GetCurrentProcessId()) + "-" +
                 std::to_string(sequence.fetch_add(1)));
        std::filesystem::create_directory(path_);
    }

    ~ScopedTestDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    ScopedTestDirectory(const ScopedTestDirectory&) = delete;
    ScopedTestDirectory& operator=(const ScopedTestDirectory&) = delete;

    std::filesystem::path file(std::string_view name) const {
        return path_ / name;
    }

private:
    std::filesystem::path path_;
};

#define TEST(name) \
    static void test_##name(); \
    static struct _reg_##name { \
        _reg_##name() { g_tests.push_back({#name, test_##name}); } \
    } _inst_##name; \
    static void test_##name()

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        std::ostringstream ss; \
        ss << __FILE__ << ":" << __LINE__ << ": " << #expr; \
        throw std::runtime_error(ss.str()); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream ss; \
        ss << __FILE__ << ":" << __LINE__ << ": " << #a << " != " << #b; \
        throw std::runtime_error(ss.str()); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

struct TestEntry { std::string name; std::function<void()> fn; };
static std::vector<TestEntry> g_tests;

// Minimal local SOCKS5 UDP ASSOCIATE peer. It performs one handshake and
// captures one UDP datagram, keeping the component test independent of any
// external proxy or network service.
struct FakeSocks5UdpPeer {
    explicit FakeSocks5UdpPeer(bool wildcard_reply)
        : worker([this, wildcard_reply] { run(wildcard_reply); }) {}

    ~FakeSocks5UdpPeer() {
        if (worker.joinable()) worker.join();
    }

    uint16_t proxy_port() { return proxy_port_future.get(); }
    std::vector<uint8_t> received() { return received_future.get(); }

private:
    std::promise<uint16_t> proxy_port_promise;
    std::future<uint16_t> proxy_port_future = proxy_port_promise.get_future();
    std::promise<std::vector<uint8_t>> received_promise;
    std::future<std::vector<uint8_t>> received_future = received_promise.get_future();
    std::thread worker;

    void run(bool wildcard_reply) {
        try {
            asio::io_context ioc;
            asio::ip::tcp::acceptor acceptor(
                ioc, {asio::ip::address_v4::loopback(), 0});
            asio::ip::udp::socket relay(
                ioc, {asio::ip::address_v4::loopback(), 0});
            proxy_port_promise.set_value(acceptor.local_endpoint().port());

            asio::ip::tcp::socket control(ioc);
            acceptor.accept(control);

            std::array<uint8_t, 3> auth{};
            asio::read(control, asio::buffer(auth));
            const std::array<uint8_t, 2> auth_reply{0x05, 0x00};
            asio::write(control, asio::buffer(auth_reply));

            std::array<uint8_t, 10> associate{};
            asio::read(control, asio::buffer(associate));

            const auto relay_port = relay.local_endpoint().port();
            const auto reply_addr = wildcard_reply
                ? asio::ip::address_v4::any().to_bytes()
                : asio::ip::address_v4::loopback().to_bytes();
            std::array<uint8_t, 10> reply{
                0x05, 0x00, 0x00, 0x01,
                reply_addr[0], reply_addr[1], reply_addr[2], reply_addr[3],
                static_cast<uint8_t>(relay_port >> 8),
                static_cast<uint8_t>(relay_port & 0xff)};
            asio::write(control, asio::buffer(reply));

            std::array<uint8_t, 512> data{};
            asio::ip::udp::endpoint sender;
            auto n = relay.receive_from(asio::buffer(data), sender);
            received_promise.set_value(
                std::vector<uint8_t>(data.begin(), data.begin() + n));
        } catch (...) {
            try { proxy_port_promise.set_exception(std::current_exception()); }
            catch (...) {}
            try { received_promise.set_exception(std::current_exception()); }
            catch (...) {}
        }
    }
};

static bool run_udp_send(asio::io_context& ioc,
                         const std::shared_ptr<clew::Socks5UdpSession>& session,
                         std::vector<uint8_t> frame) {
    auto result = asio::co_spawn(
        ioc, session->async_send_udp(std::move(frame)), asio::use_future);
    std::thread io_thread([&ioc] { ioc.run(); });
    bool sent = result.get();
    session->close();
    ioc.stop();
    io_thread.join();
    return sent;
}

// ============================================================
// 1. wildcard_match tests
// ============================================================

using clew::wildcard_match;

TEST(wildcard_exact_match) {
    ASSERT_TRUE(wildcard_match("chrome.exe", "chrome.exe"));
    ASSERT_FALSE(wildcard_match("chrome.exe", "firefox.exe"));
}

TEST(wildcard_star) {
    ASSERT_TRUE(wildcard_match("chrome*", "chrome.exe"));
    ASSERT_TRUE(wildcard_match("*chrome*", "google-chrome.exe"));
    ASSERT_TRUE(wildcard_match("*.exe", "test.exe"));
    ASSERT_FALSE(wildcard_match("*.dll", "test.exe"));
}

TEST(wildcard_question) {
    ASSERT_TRUE(wildcard_match("?.exe", "a.exe"));
    ASSERT_FALSE(wildcard_match("?.exe", "ab.exe"));
    ASSERT_TRUE(wildcard_match("test?.exe", "test1.exe"));
}

TEST(wildcard_case_insensitive) {
    ASSERT_TRUE(wildcard_match("Chrome.EXE", "chrome.exe"));
    ASSERT_TRUE(wildcard_match("PYTHON*", "python3.11.exe"));
}

TEST(wildcard_empty) {
    ASSERT_TRUE(wildcard_match("", ""));
    ASSERT_FALSE(wildcard_match("", "something"));
    ASSERT_FALSE(wildcard_match("something", ""));
}

TEST(wildcard_complex) {
    ASSERT_TRUE(wildcard_match("*py*on*", "python.exe"));
    ASSERT_TRUE(wildcard_match("c?r?.exe", "curl.exe"));
    ASSERT_FALSE(wildcard_match("c?r?.exe", "cargo.exe"));
}

// ============================================================
// 2. cmdline_match tests
// ============================================================

using clew::cmdline_match;

TEST(cmdline_keyword_mode) {
    // No wildcards → keyword mode: all fragments must appear as substrings
    ASSERT_TRUE(cmdline_match("udp_client", "C:\\Python\\python.exe udp_client.py --port 8080"));
    ASSERT_TRUE(cmdline_match("udp_client 8080", "C:\\Python\\python.exe udp_client.py --port 8080"));
    ASSERT_FALSE(cmdline_match("udp_client 9090", "C:\\Python\\python.exe udp_client.py --port 8080"));
}

TEST(cmdline_keyword_order_independent) {
    ASSERT_TRUE(cmdline_match("8080 udp_client", "python.exe udp_client.py --port 8080"));
}

TEST(cmdline_glob_mode) {
    // Contains * or ? → glob mode
    ASSERT_TRUE(cmdline_match("*udp_client*", "C:\\Python\\python.exe udp_client.py"));
    ASSERT_FALSE(cmdline_match("*udp_client*8080*", "python.exe udp_client.py --port 9090"));
    ASSERT_TRUE(cmdline_match("*udp_client*8080*", "python.exe udp_client.py --port 8080"));
}

TEST(cmdline_empty_pattern) {
    // Empty pattern should match anything (but cmdline_match is not called with empty)
    // The engine checks emptiness before calling, so test the function directly
    ASSERT_TRUE(cmdline_match("", "anything"));
}

// ============================================================
// 3. flat_tree tests
// ============================================================

using clew::flat_tree;
using clew::INVALID_IDX;
using clew::NO_PROXY;
using clew::ROOT_PSN_SENTINEL;

// Test helpers — translate legacy add/tombstone signatures (pre-PSN refactor)
// onto the new PSN-keyed interface. PSNs are assigned monotonically per
// add_test_entry invocation; parent_psn is looked up from side_map.
static uint64_t g_next_test_psn = 1;

static uint32_t add_test_entry(flat_tree& t, DWORD pid, DWORD parent_pid,
                               FILETIME ft, const wchar_t* name) {
    uint64_t my_psn = g_next_test_psn++;
    uint64_t parent_psn = ROOT_PSN_SENTINEL;
    if (parent_pid != 0) {
        auto& sm = t.side_map();
        if (auto it = sm.find(parent_pid); it != sm.end()) {
            parent_psn = it->second.psn;
        }
    }
    uint32_t idx = t.add_entry(pid, parent_pid, my_psn, parent_psn, ft, name);
    if (parent_psn == ROOT_PSN_SENTINEL || parent_pid == 0) {
        t.mark_root(idx);
    } else {
        uint32_t pidx = t.find_by_pid_psn(parent_pid, parent_psn);
        if (pidx != INVALID_IDX) {
            t.attach_child(pidx, idx);
        } else {
            t.mark_root(idx);
        }
    }
    return idx;
}

static bool tombstone_by_pid(flat_tree& t, DWORD pid) {
    auto& sm = t.side_map();
    auto it = sm.find(pid);
    if (it == sm.end()) return false;
    return t.tombstone(pid, it->second.psn);
}

static flat_tree make_test_tree() {
    flat_tree tree;
    FILETIME ft{};
    add_test_entry(tree, 4,   0,   ft, L"System");
    add_test_entry(tree, 100, 4,   ft, L"init.exe");
    add_test_entry(tree, 200, 100, ft, L"chrome.exe");
    add_test_entry(tree, 201, 200, ft, L"chrome.exe");
    add_test_entry(tree, 202, 200, ft, L"chrome.exe");
    add_test_entry(tree, 300, 100, ft, L"python.exe");
    return tree;
}

TEST(tree_build_and_find) {
    auto tree = make_test_tree();
    ASSERT_TRUE(tree.find_by_pid(4) != INVALID_IDX);
    ASSERT_TRUE(tree.find_by_pid(200) != INVALID_IDX);
    ASSERT_TRUE(tree.find_by_pid(999) == INVALID_IDX);
    ASSERT_EQ(tree.alive_count(), 6u);
}

TEST(tree_entry_name) {
    auto tree = make_test_tree();
    uint32_t idx = tree.find_by_pid(200);
    ASSERT_EQ(std::string(tree.at(idx).name_u8), std::string("chrome.exe"));
}

TEST(tree_parent_child) {
    auto tree = make_test_tree();
    uint32_t chrome_idx = tree.find_by_pid(200);
    uint32_t init_idx = tree.find_by_pid(100);
    ASSERT_EQ(tree.at(chrome_idx).parent_pid, (DWORD)100);
    // Chrome (200) should be a child of init (100)
    ASSERT_TRUE(tree.at(chrome_idx).parent_index == init_idx);
}

TEST(tree_add_entry) {
    auto tree = make_test_tree();
    uint32_t old_count = tree.alive_count();
    FILETIME ft = {};
    add_test_entry(tree, 400, 200, ft, L"helper.exe");
    ASSERT_EQ(tree.alive_count(), old_count + 1);
    uint32_t idx = tree.find_by_pid(400);
    ASSERT_TRUE(idx != INVALID_IDX);
    ASSERT_EQ(std::string(tree.at(idx).name_u8), std::string("helper.exe"));
}

TEST(tree_tombstone) {
    auto tree = make_test_tree();
    uint32_t count_before = tree.alive_count();
    tombstone_by_pid(tree, 300);  // Remove python.exe
    ASSERT_EQ(tree.alive_count(), count_before - 1);
    // PID still findable but marked dead
    uint32_t idx = tree.find_by_pid(300);
    ASSERT_TRUE(idx == INVALID_IDX || !tree.at(idx).alive);
}

TEST(tree_visit_descendants) {
    auto tree = make_test_tree();
    uint32_t chrome_idx = tree.find_by_pid(200);
    std::vector<DWORD> descendants;
    tree.visit_descendants(chrome_idx, [&descendants](uint32_t, const auto& entry) {
        descendants.push_back(entry.pid);
    });
    // Chrome 200 has children 201, 202
    ASSERT_EQ(descendants.size(), 2u);
    ASSERT_TRUE(std::find(descendants.begin(), descendants.end(), 201) != descendants.end());
    ASSERT_TRUE(std::find(descendants.begin(), descendants.end(), 202) != descendants.end());
}

TEST(tree_compact) {
    auto tree = make_test_tree();
    // Tombstone several entries
    tombstone_by_pid(tree, 201);
    tombstone_by_pid(tree, 202);
    tombstone_by_pid(tree, 300);
    uint32_t alive_before = tree.alive_count();
    tree.compact();
    ASSERT_EQ(tree.alive_count(), alive_before);
    ASSERT_EQ(tree.tombstone_count(), 0u);
    // Remaining PIDs still findable
    ASSERT_TRUE(tree.find_by_pid(4) != INVALID_IDX);
    ASSERT_TRUE(tree.find_by_pid(200) != INVALID_IDX);
}

// ============================================================
// 4. rule_engine_v3 tests
// ============================================================

using clew::rule_engine_v3;
using clew::AutoRule;

static AutoRule make_rule(std::string_view name, std::string_view process_name,
                          bool hack_tree = false, uint32_t group_id = 1) {
    AutoRule r;
    r.id = std::format("rule_{}", name);
    r.name = name;
    r.enabled = true;
    r.process_name = process_name;
    r.hack_tree = hack_tree;
    r.proxy_group_id = group_id;
    r.protocol = "tcp";
    return r;
}

TEST(rule_auto_match_simple) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("chrome_rule", "chrome.exe")});
    engine.apply_auto_rules(tree);

    // All chrome.exe processes should be proxied
    auto hijacked = engine.get_hijacked_pids(tree);
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 200) != hijacked.end());
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 201) != hijacked.end());
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 202) != hijacked.end());
    // python.exe should not be
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 300) == hijacked.end());
}

TEST(rule_auto_match_wildcard) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("star_rule", "chr*")});
    engine.apply_auto_rules(tree);

    auto hijacked = engine.get_hijacked_pids(tree);
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 200) != hijacked.end());
}

TEST(rule_hack_tree) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("chrome_tree", "chrome.exe", true)});
    engine.apply_auto_rules(tree);

    // hack_tree: chrome.exe matches → root (200) + all descendants (201, 202)
    auto hijacked = engine.get_hijacked_pids(tree);
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 200) != hijacked.end());
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 201) != hijacked.end());
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 202) != hijacked.end());
}

TEST(rule_on_process_start) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("py_rule", "python.exe")});
    engine.apply_auto_rules(tree);

    // Simulate new python process starting
    FILETIME ft = {};
    uint32_t idx = add_test_entry(tree, 500, 100, ft, L"python.exe");
    auto match = engine.on_process_start(tree, idx);
    ASSERT_TRUE(match.has_value());
    ASSERT_EQ(match.value(), std::string("rule_py_rule"));
    ASSERT_TRUE(tree.at(idx).is_proxied());
}

TEST(rule_manual_hijack) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;

    engine.manual_hijack(tree, 300, 1);  // hijack python.exe
    ASSERT_TRUE(engine.is_manually_hijacked(tree, 300));

    auto hijacked = engine.get_hijacked_pids(tree);
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 300) != hijacked.end());

    engine.manual_unhijack(tree, 300);
    ASSERT_FALSE(engine.is_manually_hijacked(tree, 300));
}

TEST(rule_exclude_pid) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("chrome_rule", "chrome.exe")});

    // Exclude PID 201 before applying
    engine.exclude_pid(tree, "rule_chrome_rule", 201);
    engine.apply_auto_rules(tree);

    auto hijacked = engine.get_hijacked_pids(tree);
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 200) != hijacked.end());
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 201) == hijacked.end());  // excluded
    ASSERT_TRUE(std::find(hijacked.begin(), hijacked.end(), 202) != hijacked.end());
}

TEST(rule_disabled) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    auto rule = make_rule("disabled_rule", "chrome.exe");
    rule.enabled = false;
    engine.set_auto_rules({rule});
    engine.apply_auto_rules(tree);

    auto hijacked = engine.get_hijacked_pids(tree);
    ASSERT_TRUE(hijacked.empty());
}

TEST(rule_on_process_exit) {
    auto tree = make_test_tree();
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("py_rule", "python.exe")});
    engine.apply_auto_rules(tree);

    // Process exit should clean up matched_pids
    engine.on_process_exit(300);
    // Verify rule's internal state is cleaned
    ASSERT_TRUE(engine.auto_rules()[0].matched_pids.find(300) ==
                engine.auto_rules()[0].matched_pids.end());
}

// ============================================================
// 4b. Bug repro: orphan reparent + hack_tree mis-inheritance
// ============================================================

// Bug 1: reparent_children doesn't update parent_pid.
// After compact, rebuild_lc_rs_links uses stale parent_pid → wrong topology.
// Then apply_auto_rules expands descendants of wrong subtree.
TEST(bug_reparent_stale_parent_pid_after_compact) {
    // Post-PSN refactor: parent_psn (NOT parent_pid) is the disambiguating
    // tag during rebuild_lc_rs_links. PID-reuse no longer corrupts topology
    // because the new PID owner has a fresh PSN that doesn't match the
    // dead launcher's PSN.
    //
    // Tree:
    //   System(4)
    //   ├── spotify.exe(100)
    //   │   └── chrome.exe(101)   ← Spotify's Chromium
    //   └── launcher.exe(200)
    //       └── chrome.exe(300)   ← Google Chrome browser
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4,   0,   ft, L"System");
    add_test_entry(tree, 100, 4,   ft, L"spotify.exe");
    add_test_entry(tree, 101, 100, ft, L"chrome.exe");    // Spotify child
    add_test_entry(tree, 200, 4,   ft, L"launcher.exe");  // Chrome launcher
    add_test_entry(tree, 300, 200, ft, L"chrome.exe");    // Google Chrome, parent=200

    // Apply hack_tree rule for spotify.exe → matches PID 100, expands to 101
    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("spotify", "spotify.exe", true, 1)});
    engine.apply_auto_rules(tree);

    // Verify: only spotify subtree is proxied
    ASSERT_TRUE(tree.at(tree.find_by_pid(100)).is_proxied());  // spotify
    ASSERT_TRUE(tree.at(tree.find_by_pid(101)).is_proxied());  // spotify's chrome
    ASSERT_FALSE(tree.at(tree.find_by_pid(300)).is_proxied()); // Google Chrome NOT proxied

    // launcher.exe(200) dies → chrome.exe(300) reparented to System(4)
    tombstone_by_pid(tree, 200);

    uint32_t chrome_idx = tree.find_by_pid(300);
    ASSERT_TRUE(chrome_idx != INVALID_IDX);
    ASSERT_EQ(tree.at(chrome_idx).parent_pid, (DWORD)4);

    // Now PID 200 gets recycled as a Spotify chrome.exe child.
    // The new entry gets a fresh PSN (post-launcher), so even though
    // chrome.exe(300) still has parent_pid=200 from rebuild's view, the
    // parent_psn field on chrome(300) points to the now-dead launcher's
    // PSN and won't match the new entry.
    add_test_entry(tree, 200, 100, ft, L"chrome.exe");
    engine.apply_auto_rules(tree);
    ASSERT_TRUE(tree.at(tree.find_by_pid(200)).is_proxied());

    // Trigger compact (need enough tombstones for the 20% threshold).
    add_test_entry(tree, 501, 4, ft, L"tmp1.exe");
    add_test_entry(tree, 502, 4, ft, L"tmp2.exe");
    tombstone_by_pid(tree, 501);
    tombstone_by_pid(tree, 502);
    tree.compact();

    // After compact + rebuild_lc_rs_links: chrome.exe(300) was reparented
    // to System(4) by reparent_children — its parent_psn now points to
    // System's PSN. The new chrome.exe(200) has an unrelated PSN.
    // rebuild matches by parent_psn, so chrome(300) correctly lands under
    // System.
    engine.apply_auto_rules(tree);
    ASSERT_FALSE(tree.at(tree.find_by_pid(300)).is_proxied());
}

// Bug 2: on_process_start tree inheritance uses parent_pid (can be stale/recycled)
// A new process whose parent_pid was once in matched_pids gets incorrectly inherited.
TEST(bug_tree_inherit_stale_matched_pid) {
    // Same scenario as before — the rule engine still uses parent_pid for
    // tree inheritance lookups. The PSN refactor doesn't fix this codepath
    // (the matched_pids set is keyed by PID), so behavior unchanged here.
    //
    // Tree:
    //   System(4)
    //   ├── spotify.exe(100)
    //   │   └── chrome.exe(101)
    //   └── explorer.exe(50)
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4,   0,   ft, L"System");
    add_test_entry(tree, 50,  4,   ft, L"explorer.exe");
    add_test_entry(tree, 100, 4,   ft, L"spotify.exe");
    add_test_entry(tree, 101, 100, ft, L"chrome.exe");

    rule_engine_v3 engine;
    engine.set_auto_rules({make_rule("spotify", "spotify.exe", true, 1)});
    engine.apply_auto_rules(tree);

    ASSERT_TRUE(tree.at(tree.find_by_pid(101)).is_proxied());
    ASSERT_TRUE(engine.auto_rules()[0].matched_pids.count(101) > 0);

    tombstone_by_pid(tree, 101);
    engine.on_process_exit(101);
    ASSERT_TRUE(engine.auto_rules()[0].matched_pids.count(101) == 0);

    // PID 101 recycled with explorer parent — should NOT match spotify rule.
    uint32_t new_idx = add_test_entry(tree, 101, 50, ft, L"notepad.exe");
    auto match = engine.on_process_start(tree, new_idx);
    ASSERT_FALSE(match.has_value());

    // Edge case: re-add chrome(101) under spotify, PID 999 child claims 101.
    tombstone_by_pid(tree, 101);
    add_test_entry(tree, 101, 100, ft, L"chrome.exe");
    engine.apply_auto_rules(tree);
    ASSERT_TRUE(engine.auto_rules()[0].matched_pids.count(101) > 0);

    uint32_t child_idx = add_test_entry(tree, 999, 101, ft, L"gpu-process.exe");
    auto match2 = engine.on_process_start(tree, child_idx);
    ASSERT_TRUE(match2.has_value());  // Tree-inherited from chrome(101)
}

// ============================================================
// 5. PortTracker tests
// ============================================================

using clew::PortTracker;
using clew::TrackerEntry;
using clew::slot_state;
using clew::publish_outcome;
using clew::NO_POOL_IDX;

static TrackerEntry make_entry(uint32_t ip, uint16_t port, uint32_t group) {
    TrackerEntry e;
    e.remote_addr[0] = ip;
    e.remote_port    = port;
    e.group_id       = group;
    return e;
}

TEST(port_tracker_publish_proxied_on_empty) {
    auto pt = std::make_unique<PortTracker>();
    auto e = make_entry(0x0A000001, 443, 1);   // 10.0.0.1:443

    ASSERT_FALSE(pt->should_reflect(8080));
    auto r = pt->publish(8080, slot_state::proxied, e, /*connect_ts=*/1000);
    ASSERT_TRUE(r.outcome == publish_outcome::stored);
    ASSERT_TRUE(pt->should_reflect(8080));
    ASSERT_EQ(pt->peek(8080).remote_port, (uint16_t)443);
    ASSERT_EQ(pt->peek(8080).group_id, 1u);
}

TEST(port_tracker_direct_does_not_reflect) {
    auto pt = std::make_unique<PortTracker>();
    pt->publish(8081, slot_state::direct, make_entry(1, 80, 0), 1000);
    ASSERT_TRUE(pt->state(8081) == slot_state::direct);
    ASSERT_FALSE(pt->should_reflect(8081));
}

TEST(port_tracker_take_carries_timestamp) {
    auto pt = std::make_unique<PortTracker>();
    pt->publish(9090, slot_state::proxied, make_entry(1, 80, 2), 4242);

    auto t = pt->take(9090);
    ASSERT_TRUE(t.has_value());
    ASSERT_EQ(t->entry.remote_port, (uint16_t)80);
    ASSERT_EQ(t->connect_ts, (int64_t)4242);
    // take() is non-destructive: the NETWORK layer keeps reflecting
    ASSERT_TRUE(pt->should_reflect(9090));

    // direct slots are not the relay's business
    pt->publish(9091, slot_state::direct, make_entry(1, 80, 0), 1);
    ASSERT_FALSE(pt->take(9091).has_value());
    ASSERT_FALSE(pt->take(12345).has_value());
}

TEST(port_tracker_clear_if_matches_timestamp_only) {
    auto pt = std::make_unique<PortTracker>();
    pt->publish(5000, slot_state::proxied, make_entry(1, 22, 0), 100);
    // Newer flow reused the port and published before the old relay tore down
    pt->publish(5000, slot_state::proxied, make_entry(2, 22, 0), 200);

    ASSERT_FALSE(pt->clear_if(5000, 100));          // old relay: no-op
    ASSERT_TRUE(pt->should_reflect(5000));
    ASSERT_TRUE(pt->clear_if(5000, 200));           // current flow: cleared
    ASSERT_TRUE(pt->state(5000) == slot_state::empty);
    ASSERT_FALSE(pt->clear_if(5000, 200));          // already empty
}

TEST(port_tracker_park_then_publish_returns_parked_ref) {
    auto pt = std::make_unique<PortTracker>();
    auto v = pt->load(7000);
    ASSERT_TRUE(v.state() == slot_state::empty);

    ASSERT_TRUE(pt->try_park(7000, v.word, /*gen=*/5, /*idx=*/17));
    ASSERT_TRUE(pt->state(7000) == slot_state::pending);
    ASSERT_FALSE(pt->should_reflect(7000));
    // A second SYN while pending must see pending (caller drops it)
    ASSERT_FALSE(pt->try_park(7000, v.word, 6, 18));

    auto r = pt->publish(7000, slot_state::proxied, make_entry(1, 443, 3), 900);
    ASSERT_TRUE(r.outcome == publish_outcome::released_parked);
    ASSERT_EQ(r.parked.idx, 17u);
    ASSERT_EQ(r.parked.gen, 5u);
    ASSERT_TRUE(pt->should_reflect(7000));
}

TEST(port_tracker_watchdog_pin_rejects_late_decision) {
    auto pt = std::make_unique<PortTracker>();
    auto v = pt->load(7001);
    ASSERT_TRUE(pt->try_park(7001, v.word, 1, 0));

    // Watchdog releases the parked SYN (kernel ts 500) and pins the port
    auto pending = pt->load(7001);
    ASSERT_TRUE(pt->pin_abandoned(7001, pending.word, /*syn_ts=*/500));
    ASSERT_TRUE(pt->state(7001) == slot_state::abandoned);

    // The CONNECT for that same flow (older than the SYN) arrives late: rejected
    auto late = pt->publish(7001, slot_state::proxied, make_entry(1, 443, 1), 480);
    ASSERT_TRUE(late.outcome == publish_outcome::late_rejected);
    ASSERT_TRUE(pt->state(7001) == slot_state::abandoned);
    ASSERT_FALSE(pt->should_reflect(7001));

    // A genuinely new flow on the reused port (CONNECT newer than the pin) wins
    auto fresh = pt->publish(7001, slot_state::proxied, make_entry(2, 443, 1), 600);
    ASSERT_TRUE(fresh.outcome == publish_outcome::stored);
    ASSERT_TRUE(pt->should_reflect(7001));
}

TEST(port_tracker_echo_connect_is_recognised) {
    auto pt = std::make_unique<PortTracker>();
    const uint32_t remote[4] = {0x01010101, 0, 0, 0};
    auto e = make_entry(0x01010101, 443, 1);
    pt->publish(7002, slot_state::proxied, e, 1000);

    // Same remote, well inside the TTL: our own re-injected SYN's CONNECT
    ASSERT_TRUE(pt->is_echo(7002, 1000 + pt->ms_to_ticks(1), remote, 443));
    // Different remote endpoint: a real new flow
    const uint32_t other[4] = {0x02020202, 0, 0, 0};
    ASSERT_FALSE(pt->is_echo(7002, 1000 + pt->ms_to_ticks(1), other, 443));
    ASSERT_FALSE(pt->is_echo(7002, 1000 + pt->ms_to_ticks(1), remote, 444));
    // Same remote but older than the TTL: stale slot, not an echo
    ASSERT_FALSE(pt->is_echo(7002, 1000 + pt->ms_to_ticks(11), remote, 443));
    // Empty / pending slots are never echoes
    ASSERT_FALSE(pt->is_echo(7003, 1000, remote, 443));
}

TEST(port_tracker_close_state_machine) {
    auto pt = std::make_unique<PortTracker>();

    // direct -> cleared by CLOSE
    pt->publish(7010, slot_state::direct, make_entry(1, 80, 0), 100);
    ASSERT_FALSE(pt->on_close(7010, 150).has_value());
    ASSERT_TRUE(pt->state(7010) == slot_state::empty);

    // proxied -> CLOSE leaves it to the relay
    pt->publish(7011, slot_state::proxied, make_entry(1, 80, 0), 100);
    ASSERT_FALSE(pt->on_close(7011, 150).has_value());
    ASSERT_TRUE(pt->should_reflect(7011));

    // stale CLOSE (older than the slot's CONNECT) is ignored
    pt->publish(7012, slot_state::direct, make_entry(1, 80, 0), 300);
    ASSERT_FALSE(pt->on_close(7012, 250).has_value());
    ASSERT_TRUE(pt->state(7012) == slot_state::direct);

    // pending -> CLOSE empties the slot and hands back the pool index
    auto v = pt->load(7013);
    ASSERT_TRUE(pt->try_park(7013, v.word, 9, 42));
    auto idx = pt->on_close(7013, 150);
    ASSERT_TRUE(idx.has_value());
    ASSERT_EQ(*idx, 42u);
    ASSERT_TRUE(pt->state(7013) == slot_state::empty);

    // abandoned -> cleared by CLOSE
    v = pt->load(7014);
    ASSERT_TRUE(pt->try_park(7014, v.word, 1, 1));
    ASSERT_TRUE(pt->pin_abandoned(7014, pt->load(7014).word, 500));
    ASSERT_FALSE(pt->on_close(7014, 600).has_value());
    ASSERT_TRUE(pt->state(7014) == slot_state::empty);

    // empty -> nothing
    ASSERT_FALSE(pt->on_close(7015, 1).has_value());
}

TEST(port_tracker_isn_retransmit_vs_new_flow) {
    auto pt = std::make_unique<PortTracker>();
    // A direct flow on port 7020 whose SYN carried ISN 0xAABBCCDD
    pt->publish(7020, slot_state::direct, make_entry(1, 443, 0), 1000);
    pt->note_syn(7020, 0xAABBCCDDu);

    // Same ISN again (retransmit, >= 1s later so far past the TTL): recognised
    ASSERT_TRUE(pt->is_retransmit(7020, 0xAABBCCDDu));
    // Different ISN on the same port and remote: a new connection, must NOT
    // be swallowed by the retransmit exception -> takes the TTL/park path
    ASSERT_FALSE(pt->is_retransmit(7020, 0xAABBCCDEu));
    // Nothing recorded on a port we never saw a SYN on
    ASSERT_FALSE(pt->is_retransmit(7021, 0xAABBCCDDu));

    // The new flow's SYN replaces the recorded ISN; the old one no longer matches
    pt->note_syn(7020, 0x11223344u);
    ASSERT_FALSE(pt->is_retransmit(7020, 0xAABBCCDDu));
    ASSERT_TRUE(pt->is_retransmit(7020, 0x11223344u));
    ASSERT_EQ(sizeof(clew::TrackerSlot), (size_t)64);
}

TEST(port_tracker_word_packing) {
    using clew::pack_word; using clew::word_state; using clew::word_gen; using clew::word_idx;
    const uint64_t w = pack_word(slot_state::pending, 0xABCDEFu, 123456789u);
    ASSERT_TRUE(word_state(w) == slot_state::pending);
    ASSERT_EQ(word_gen(w), 0xABCDEFu);
    ASSERT_EQ(word_idx(w), 123456789u);
    // generation is 24 bits: high bits are masked, never leak into the state byte
    const uint64_t w2 = pack_word(slot_state::direct, 0xFFFFFFFFu, NO_POOL_IDX);
    ASSERT_TRUE(word_state(w2) == slot_state::direct);
    ASSERT_EQ(word_gen(w2), 0xFFFFFFu);
    ASSERT_EQ(word_idx(w2), NO_POOL_IDX);
    ASSERT_EQ(sizeof(clew::TrackerSlot), (size_t)64);
}

// ---- syn_parker pool (no injector thread started: pure pool semantics) ----

TEST(syn_parker_pool_alloc_free_generation) {
    auto pt = std::make_unique<PortTracker>();
    clew::syn_parker parker(*pt, /*watchdog_ms=*/20, /*pool_size=*/32);
    ASSERT_EQ(parker.pool_size(), 32u);
    ASSERT_EQ(parker.watchdog_ms(), 20);

    uint8_t pkt[64] = {1, 2, 3};
    WINDIVERT_ADDRESS addr{};
    addr.Timestamp = 777;

    auto a = parker.park(pkt, sizeof(pkt), addr, 5555);
    ASSERT_TRUE(a.idx != NO_POOL_IDX);
    ASSERT_EQ(parker.snapshot().pool_in_use, 1u);

    // Freeing bumps the generation, so a stale ref can never match the next owner
    parker.free_slot(a.idx);
    ASSERT_EQ(parker.snapshot().pool_in_use, 0u);
    auto b = parker.park(pkt, sizeof(pkt), addr, 5556);
    ASSERT_TRUE(b.idx != NO_POOL_IDX);
    bool reused_same_idx = (b.idx == a.idx);
    if (reused_same_idx) ASSERT_EQ(b.gen, a.gen + 1);
    parker.free_slot(b.idx);
}

TEST(syn_parker_pool_exhaustion_returns_no_idx) {
    auto pt = std::make_unique<PortTracker>();
    clew::syn_parker parker(*pt, 20, 32);   // MIN_POOL
    uint8_t pkt[8] = {};
    WINDIVERT_ADDRESS addr{};

    std::vector<uint32_t> held;
    for (uint32_t i = 0; i < 32; ++i) {
        auto r = parker.park(pkt, sizeof(pkt), addr, static_cast<uint16_t>(1000 + i));
        ASSERT_TRUE(r.idx != NO_POOL_IDX);
        held.push_back(r.idx);
    }
    ASSERT_EQ(parker.snapshot().pool_in_use, 32u);
    ASSERT_EQ(parker.snapshot().pool_peak, 32u);

    auto full = parker.park(pkt, sizeof(pkt), addr, 2000);
    ASSERT_EQ(full.idx, NO_POOL_IDX);

    for (auto idx : held) parker.free_slot(idx);
    ASSERT_EQ(parker.snapshot().pool_in_use, 0u);   // the leak signal: back to zero
    auto again = parker.park(pkt, sizeof(pkt), addr, 2001);
    ASSERT_TRUE(again.idx != NO_POOL_IDX);
    parker.free_slot(again.idx);
}

TEST(syn_parker_config_is_clamped) {
    auto pt = std::make_unique<PortTracker>();
    clew::syn_parker low(*pt, 1, 4);
    ASSERT_EQ(low.watchdog_ms(), clew::syn_parker::MIN_WATCHDOG_MS);
    ASSERT_EQ(low.pool_size(), clew::syn_parker::MIN_POOL);
    clew::syn_parker high(*pt, 500, 100000);
    ASSERT_EQ(high.watchdog_ms(), clew::syn_parker::MAX_WATCHDOG_MS);
    ASSERT_EQ(high.pool_size(), clew::syn_parker::MAX_POOL);
}

// A PID recycled before its ETW STOP arrives: the rule engine still holds the
// old owner in matched_pids, and try_match_one skips PIDs it already holds.
// The manager therefore calls on_process_exit(pid) before inserting the new
// owner (process_tree_manager::handle_start_or_rundown). This pins the
// engine behaviour that sequence relies on.
TEST(rule_engine_recycled_pid_needs_exit_before_rematch) {
    clew::flat_tree tree;
    clew::rule_engine_v3 engine;
    clew::AutoRule rule;
    rule.id = "curl"; rule.name = "curl"; rule.enabled = true;
    rule.process_name = "curl.exe"; rule.hack_tree = true; rule.proxy_group_id = 3;
    engine.set_auto_rules({rule});

    FILETIME ft{};
    uint32_t old_idx = add_test_entry(tree, 5000, 1, ft, L"curl.exe");   // PSN n
    ASSERT_TRUE(engine.on_process_start(tree, old_idx).has_value());
    ASSERT_EQ(tree.at(old_idx).group_id, 3u);

    // Same PID, new PSN (add_test_entry allocates a fresh one), no
    // on_process_exit in between: the engine skips it.
    uint32_t new_idx = add_test_entry(tree, 5000, 1, ft, L"curl.exe");   // PSN n+1
    ASSERT_TRUE(new_idx != old_idx);
    ASSERT_FALSE(engine.on_process_start(tree, new_idx).has_value());
    ASSERT_EQ(tree.at(new_idx).group_id, clew::NO_PROXY);

    // With the exit hook first (what the manager does), the new owner matches.
    engine.on_process_exit(5000);
    ASSERT_TRUE(engine.on_process_start(tree, new_idx).has_value());
    ASSERT_EQ(tree.at(new_idx).group_id, 3u);
}

TEST(tcp_syn_parking_config_defaults_and_roundtrip) {
    clew::ConfigV2 def;
    ASSERT_TRUE(def.tcp_syn_parking.enabled);
    ASSERT_EQ(def.tcp_syn_parking.watchdog_ms, 20);
    ASSERT_EQ(def.tcp_syn_parking.pool_size, 256);

    // Old config files without the block keep the defaults
    auto old = nlohmann::json::parse(R"({"version": 2})").get<clew::ConfigV2>();
    ASSERT_TRUE(old.tcp_syn_parking.enabled);

    auto off = nlohmann::json::parse(R"({"version": 2, "tcp_syn_parking": {"enabled": false, "watchdog_ms": 10}})")
                   .get<clew::ConfigV2>();
    ASSERT_FALSE(off.tcp_syn_parking.enabled);
    ASSERT_EQ(off.tcp_syn_parking.watchdog_ms, 10);
    ASSERT_EQ(off.tcp_syn_parking.pool_size, 256);

    nlohmann::json out = off;
    ASSERT_TRUE(out.contains("tcp_syn_parking"));
    ASSERT_FALSE(out["tcp_syn_parking"]["enabled"].get<bool>());
}

// ============================================================
// 6. TrafficFilter tests
// ============================================================

using clew::TrafficFilter;
using clew::TrafficFilterEngine;
using clew::CidrRange;
using clew::PortRange;
using clew::IpExcludePolicy;
using clew::IpExcludeReason;
using clew::UdpTrackerEntry;
using clew::UdpPortTracker;
using clew::PolicyTable;
using clew::PolicyPublisher;
using clew::PolicyReader;
using clew::GLOBAL_ONLY_POLICY;

TEST(filter_empty_allows_all) {
    TrafficFilter f;
    ASSERT_TRUE(TrafficFilterEngine::should_proxy("8.8.8.8", 443, f));
    ASSERT_TRUE(TrafficFilterEngine::should_proxy("1.2.3.4", 80, f));
}

TEST(filter_exclude_cidr) {
    TrafficFilter f;
    f.exclude_cidrs = {CidrRange::parse("10.0.0.0/8")};
    ASSERT_FALSE(TrafficFilterEngine::should_proxy("10.0.0.1", 443, f));
    ASSERT_FALSE(TrafficFilterEngine::should_proxy("10.255.255.255", 80, f));
    ASSERT_TRUE(TrafficFilterEngine::should_proxy("11.0.0.1", 443, f));
}

TEST(filter_include_ports) {
    TrafficFilter f;
    f.include_ports = {PortRange::parse("443"), PortRange::parse("80")};
    ASSERT_TRUE(TrafficFilterEngine::should_proxy("8.8.8.8", 443, f));
    ASSERT_TRUE(TrafficFilterEngine::should_proxy("8.8.8.8", 80, f));
    ASSERT_FALSE(TrafficFilterEngine::should_proxy("8.8.8.8", 22, f));
}

TEST(filter_exclude_port) {
    TrafficFilter f;
    f.exclude_ports = {PortRange::parse("22")};
    ASSERT_FALSE(TrafficFilterEngine::should_proxy("8.8.8.8", 22, f));
    ASSERT_TRUE(TrafficFilterEngine::should_proxy("8.8.8.8", 443, f));
}

TEST(ip_exclude_policy_global_precedes_rule) {
    IpExcludePolicy policy;
    policy.global_cidrs = {CidrRange::parse("192.0.2.0/24")};
    policy.rule_cidrs = {CidrRange::parse("192.0.2.0/25")};
    ASSERT_EQ(policy.evaluate(CidrRange::ip_to_uint("192.0.2.13")),
              IpExcludeReason::global);
    ASSERT_EQ(policy.evaluate(CidrRange::ip_to_uint("198.51.100.1")),
              IpExcludeReason::none);
}

TEST(ip_exclude_policy_empty_excludes_nothing) {
    IpExcludePolicy policy;
    ASSERT_EQ(policy.evaluate(CidrRange::ip_to_uint("192.0.2.1")),
              IpExcludeReason::none);
    ASSERT_EQ(policy.evaluate(CidrRange::ip_to_uint("203.0.113.1")),
              IpExcludeReason::none);
}

TEST(rule_engine_process_ip_exclude_is_scoped) {
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4, 0, ft, L"System");
    add_test_entry(tree, 100, 4, ft, L"edge.exe");
    add_test_entry(tree, 200, 4, ft, L"chrome.exe");

    auto edge = make_rule("edge", "edge.exe");
    edge.dst_filter.exclude_cidrs = {CidrRange::parse("198.51.100.0/24")};
    auto chrome = make_rule("chrome", "chrome.exe");

    rule_engine_v3 engine;
    engine.set_auto_rules({edge, chrome});
    engine.apply_auto_rules(tree);

    auto ip = CidrRange::ip_to_uint("198.51.100.13");
    ASSERT_EQ(engine.ip_exclude_reason(tree, 100, ip), IpExcludeReason::rule);
    ASSERT_EQ(engine.ip_exclude_reason(tree, 200, ip), IpExcludeReason::none);
}

TEST(rule_engine_global_exclude_covers_manual_hijack) {
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4, 0, ft, L"System");
    add_test_entry(tree, 100, 4, ft, L"manual.exe");

    rule_engine_v3 engine;
    engine.set_default_exclude_cidrs({"192.0.2.0/24"});
    engine.manual_hijack(tree, 100, 0);

    ASSERT_EQ(engine.ip_exclude_reason(tree, 100, CidrRange::ip_to_uint("192.0.2.3")),
              IpExcludeReason::global);
    ASSERT_EQ(engine.ip_exclude_reason(tree, 100, CidrRange::ip_to_uint("198.51.100.3")),
              IpExcludeReason::none);
}

TEST(rule_engine_hack_tree_inherits_ip_exclude) {
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4, 0, ft, L"System");
    add_test_entry(tree, 100, 4, ft, L"edge.exe");
    add_test_entry(tree, 101, 100, ft, L"renderer.exe");

    auto edge = make_rule("edge", "edge.exe", true);
    edge.dst_filter.exclude_cidrs = {CidrRange::parse("203.0.113.0/24")};
    rule_engine_v3 engine;
    engine.set_auto_rules({edge});
    engine.apply_auto_rules(tree);

    ASSERT_EQ(engine.ip_exclude_reason(tree, 101, CidrRange::ip_to_uint("203.0.113.2")),
              IpExcludeReason::rule);
}

TEST(udp_tracker_entry_stays_trivially_copyable) {
    // The slot array is published lock-free; a member with a non-trivial copy
    // turns a torn read into heap corruption. Mirrors the static_asserts.
    ASSERT_TRUE(std::is_trivially_copyable_v<UdpTrackerEntry>);
    ASSERT_TRUE(std::is_trivially_copyable_v<TrackerEntry>);
}

TEST(udp_tracker_carries_policy_id_to_workers) {
    auto tracker = std::make_unique<UdpPortTracker>();
    UdpTrackerEntry entry;
    entry.pid = 4242;
    entry.policy_id = 7;
    tracker->put(5353, entry);

    auto tracked = tracker->get(5353);
    ASSERT_TRUE(tracked.has_value());
    ASSERT_EQ(tracked->policy_id, 7u);
    ASSERT_EQ(tracked->pid, 4242u);

    tracker->clear(5353);
    ASSERT_TRUE(!tracker->get(5353).has_value());
    // clear() wipes the entry too, so a stale policy id can't be observed.
    ASSERT_EQ(tracker->peek(5353).policy_id, GLOBAL_ONLY_POLICY);
}

TEST(policy_table_row_lookup_and_fallback) {
    PolicyTable table;
    table.rows.resize(3);
    table.rows[GLOBAL_ONLY_POLICY].global_cidrs = {CidrRange::parse("192.0.2.0/24")};
    table.rows[2].global_cidrs = {CidrRange::parse("192.0.2.0/24")};
    table.rows[2].rule_cidrs   = {CidrRange::parse("198.51.100.0/24")};

    const auto in_global = CidrRange::ip_to_uint("192.0.2.4");
    const auto in_rule   = CidrRange::ip_to_uint("198.51.100.4");
    const auto elsewhere = CidrRange::ip_to_uint("203.0.113.4");

    ASSERT_EQ(table.evaluate(2, in_global), IpExcludeReason::global);
    ASSERT_EQ(table.evaluate(2, in_rule), IpExcludeReason::rule);
    ASSERT_EQ(table.evaluate(2, elsewhere), IpExcludeReason::none);

    // Row 0 carries global excludes only.
    ASSERT_EQ(table.evaluate(GLOBAL_ONLY_POLICY, in_rule), IpExcludeReason::none);
    ASSERT_EQ(table.evaluate(GLOBAL_ONLY_POLICY, in_global), IpExcludeReason::global);

    // A slot left over from a deleted rule falls back to row 0, never to some
    // other rule's excludes.
    ASSERT_EQ(table.evaluate(99, in_rule), IpExcludeReason::none);
    ASSERT_EQ(table.evaluate(99, in_global), IpExcludeReason::global);
}

TEST(policy_reader_picks_up_published_table) {
    PolicyPublisher publisher;
    PolicyReader reader(publisher);

    const auto ip = CidrRange::ip_to_uint("192.0.2.4");
    ASSERT_EQ(reader.evaluate(GLOBAL_ONLY_POLICY, ip), IpExcludeReason::none);

    auto table = std::make_shared<PolicyTable>();
    table->rows.resize(1);
    table->rows[GLOBAL_ONLY_POLICY].global_cidrs = {CidrRange::parse("192.0.2.0/24")};
    publisher.publish(table);

    ASSERT_EQ(reader.evaluate(GLOBAL_ONLY_POLICY, ip), IpExcludeReason::global);

    // Republishing an empty policy is picked up as well.
    auto cleared = std::make_shared<PolicyTable>();
    cleared->rows.resize(1);
    publisher.publish(cleared);
    ASSERT_EQ(reader.evaluate(GLOBAL_ONLY_POLICY, ip), IpExcludeReason::none);
}

TEST(policy_id_survives_rule_add_and_remove) {
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4, 0, ft, L"System");
    add_test_entry(tree, 100, 4, ft, L"edge.exe");

    auto edge = make_rule("edge", "edge.exe");
    edge.dst_filter.exclude_cidrs = {CidrRange::parse("198.51.100.0/24")};

    rule_engine_v3 engine;
    engine.set_auto_rules({edge});
    engine.apply_auto_rules(tree);
    const uint32_t id_before = engine.policy_id_for(tree, 100);
    ASSERT_TRUE(id_before != GLOBAL_ONLY_POLICY);

    // Insert another rule ahead of it: an index-based id would shift here.
    auto other = make_rule("other", "other.exe");
    engine.set_auto_rules({other, edge});
    engine.apply_auto_rules(tree);
    ASSERT_EQ(engine.policy_id_for(tree, 100), id_before);

    // The published table must still carry edge's excludes under that id.
    auto table = engine.build_policy_table();
    ASSERT_EQ(table->evaluate(id_before, CidrRange::ip_to_uint("198.51.100.7")),
              IpExcludeReason::rule);

    // Drop the rule: the row degrades to global-only rather than aliasing.
    engine.set_auto_rules({other});
    engine.apply_auto_rules(tree);
    auto after = engine.build_policy_table();
    ASSERT_EQ(after->evaluate(id_before, CidrRange::ip_to_uint("198.51.100.7")),
              IpExcludeReason::none);
}

TEST(policy_table_manual_hijack_gets_global_row) {
    flat_tree tree;
    FILETIME ft = {};
    add_test_entry(tree, 4, 0, ft, L"System");
    add_test_entry(tree, 100, 4, ft, L"manual.exe");

    rule_engine_v3 engine;
    engine.set_default_exclude_cidrs({"192.0.2.0/24"});
    engine.manual_hijack(tree, 100, 0);

    ASSERT_EQ(engine.policy_id_for(tree, 100), GLOBAL_ONLY_POLICY);
    auto table = engine.build_policy_table();
    ASSERT_EQ(table->evaluate(GLOBAL_ONLY_POLICY, CidrRange::ip_to_uint("192.0.2.9")),
              IpExcludeReason::global);
}

// ============================================================
// 7. SOCKS5 UDP session tests
// ============================================================

TEST(socks5_udp_binds_wildcard_and_sends_to_concrete_relay) {
    FakeSocks5UdpPeer peer(false);
    asio::io_context ioc;
    auto session = std::make_shared<clew::Socks5UdpSession>(
        ioc, "127.0.0.1", peer.proxy_port());

    ASSERT_TRUE(session->establish());
    ASSERT_TRUE(session->local_udp_endpoint().address().is_unspecified());
    ASSERT_TRUE(session->relay_endpoint().address().is_loopback());

    const std::vector<uint8_t> frame{0x05, 0x00, 0x01, 0x02, 0x03, 0x04};
    ASSERT_TRUE(run_udp_send(ioc, session, frame));
    ASSERT_EQ(peer.received(), frame);
}

TEST(socks5_udp_wildcard_relay_falls_back_to_proxy_host) {
    FakeSocks5UdpPeer peer(true);
    asio::io_context ioc;
    auto session = std::make_shared<clew::Socks5UdpSession>(
        ioc, "127.0.0.1", peer.proxy_port());

    ASSERT_TRUE(session->establish());
    ASSERT_TRUE(session->local_udp_endpoint().address().is_unspecified());
    ASSERT_EQ(session->relay_endpoint().address().to_string(),
              std::string("127.0.0.1"));

    const std::vector<uint8_t> frame{0x11, 0x22, 0x33};
    ASSERT_TRUE(run_udp_send(ioc, session, frame));
    ASSERT_EQ(peer.received(), frame);
}

TEST(socks5_udp_control_loss_marks_session_dead_and_send_fails) {
    FakeSocks5UdpPeer peer(false);
    asio::io_context ioc;
    auto session = std::make_shared<clew::Socks5UdpSession>(
        ioc, "127.0.0.1", peer.proxy_port());
    ASSERT_TRUE(session->establish());

    auto work = asio::make_work_guard(ioc);
    std::thread io_thread([&ioc] { ioc.run(); });
    const std::vector<uint8_t> first{0xaa, 0xbb};
    auto first_result = asio::co_spawn(
        ioc, session->async_send_udp(first), asio::use_future);
    ASSERT_TRUE(first_result.get());
    ASSERT_EQ(peer.received(), first);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (session->is_alive() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    ASSERT_FALSE(session->is_alive());

    auto second_result = asio::co_spawn(
        ioc, session->async_send_udp({0xcc}), asio::use_future);
    ASSERT_FALSE(second_result.get());

    session->close();
    work.reset();
    ioc.stop();
    io_thread.join();
}

// ============================================================
// 8. JSON round-trip tests
// ============================================================

using nlohmann::json;

TEST(json_autorule_roundtrip) {
    AutoRule r;
    r.id = "test_id";
    r.name = "Test Rule";
    r.enabled = true;
    r.process_name = "curl*";
    r.cmdline_pattern = "download";
    r.image_path_pattern = "C:\\tools\\";
    r.hack_tree = true;
    r.proxy_group_id = 2;
    r.protocol = "both";

    json j = r;
    AutoRule r2 = j.get<AutoRule>();

    ASSERT_EQ(r2.id, r.id);
    ASSERT_EQ(r2.name, r.name);
    ASSERT_EQ(r2.enabled, r.enabled);
    ASSERT_EQ(r2.process_name, r.process_name);
    ASSERT_EQ(r2.cmdline_pattern, r.cmdline_pattern);
    ASSERT_EQ(r2.image_path_pattern, r.image_path_pattern);
    ASSERT_EQ(r2.hack_tree, r.hack_tree);
    ASSERT_EQ(r2.proxy_group_id, r.proxy_group_id);
    ASSERT_EQ(r2.protocol, r.protocol);
}

TEST(json_autorule_defaults) {
    // Deserialize from minimal JSON — should use defaults
    json j = {{"id", "x"}, {"name", "y"}};
    AutoRule r = j.get<AutoRule>();
    ASSERT_EQ(r.enabled, true);
    ASSERT_EQ(r.hack_tree, true);  // default in from_json
    ASSERT_EQ(r.protocol, std::string("tcp"));
    ASSERT_TRUE(r.image_path_pattern.empty());
}

TEST(system_dns_restore_mode_selects_automatic_or_manual) {
    clew::system_dns::InterfaceDnsState automatic;
    automatic.automatic = true;
    automatic.dns_servers = {"192.0.2.53"};  // effective DHCP value
    ASSERT_TRUE(clew::system_dns::dns_servers_for_restore(automatic).empty());

    clew::system_dns::InterfaceDnsState manual;
    manual.automatic = false;
    manual.dns_servers = {"198.51.100.53", "203.0.113.53"};
    ASSERT_EQ(clew::system_dns::dns_servers_for_restore(manual), manual.dns_servers);
}

TEST(system_dns_explicit_nameserver_detects_configuration_mode) {
    using clew::system_dns::explicit_nameserver_is_automatic;
    ASSERT_TRUE(explicit_nameserver_is_automatic(L""));
    ASSERT_TRUE(explicit_nameserver_is_automatic(L"  \t,;\r\n"));
    ASSERT_FALSE(explicit_nameserver_is_automatic(L"198.51.100.53"));
    ASSERT_FALSE(explicit_nameserver_is_automatic(L"198.51.100.53,203.0.113.53"));
}

TEST(system_dns_nameserver_value_supports_reset_and_manual_servers) {
    using clew::system_dns::build_nameserver_value;

    const auto automatic = build_nameserver_value({});
    ASSERT_TRUE(automatic.empty());
    ASSERT_TRUE(automatic.data() != nullptr);
    ASSERT_EQ(automatic.data()[0], L'\0');

    ASSERT_EQ(build_nameserver_value({"198.51.100.53"}),
              std::wstring(L"198.51.100.53"));
    ASSERT_EQ(build_nameserver_value({"198.51.100.53", "203.0.113.53"}),
              std::wstring(L"198.51.100.53 203.0.113.53"));
}

TEST(system_dns_state_roundtrip_preserves_mode) {
    ScopedTestDirectory directory("system-dns-roundtrip");
    const auto path = directory.file("state.json");

    clew::system_dns::InterfaceDnsState automatic;
    automatic.adapter_guid = "{00000000-0000-0000-0000-000000000001}";
    automatic.friendly_name = "adapter-a";
    automatic.automatic = true;
    automatic.dns_servers = {"192.0.2.53"};

    clew::system_dns::InterfaceDnsState manual;
    manual.adapter_guid = "{00000000-0000-0000-0000-000000000002}";
    manual.friendly_name = "adapter-b";
    manual.automatic = false;
    manual.dns_servers = {"198.51.100.53", "203.0.113.53"};

    ASSERT_TRUE(clew::system_dns::save_state(path, {automatic, manual}));
    auto loaded = clew::system_dns::load_state(path);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), size_t{2});
    ASSERT_TRUE((*loaded)[0].automatic);
    ASSERT_EQ((*loaded)[0].dns_servers, automatic.dns_servers);
    ASSERT_FALSE((*loaded)[1].automatic);
    ASSERT_EQ((*loaded)[1].dns_servers, manual.dns_servers);
}

TEST(system_dns_legacy_state_defaults_to_manual_restore) {
    ScopedTestDirectory directory("system-dns-legacy");
    const auto path = directory.file("state.json");
    {
        std::ofstream out(path);
        out << R"({"interfaces":[{"adapter_guid":"legacy","friendly_name":"adapter-legacy","dns_servers":["203.0.113.53"]}]})";
    }
    auto loaded = clew::system_dns::load_state(path);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), size_t{1});
    ASSERT_FALSE((*loaded)[0].automatic);
    ASSERT_EQ(clew::system_dns::dns_servers_for_restore((*loaded)[0]),
              std::vector<std::string>{"203.0.113.53"});
}

// ============================================================
// SOCKET-layer sync resolve (unknown-PID fallback)
// ============================================================

TEST(sync_resolve_reads_live_process_identity) {
    // Smoke-test the NtQueryInformationProcess class numbers against the one
    // process we know everything about: ourselves. If class 92
    // (ProcessSequenceNumber) or class 0 (ProcessBasicInformation) were wrong,
    // the fallback would silently refuse to resolve anything.
    clew::live_process_info self;
    ASSERT_TRUE(clew::query_live_process(GetCurrentProcessId(), self));

    ASSERT_EQ(self.pid, GetCurrentProcessId());
    ASSERT_TRUE(self.psn != clew::INVALID_PSN);   // class 92 answered
    ASSERT_TRUE(self.parent_pid != 0);            // class 0 answered
    ASSERT_TRUE(self.create_time.dwLowDateTime != 0 ||
                self.create_time.dwHighDateTime != 0);

    // Name must be the basename, matching what ETW stores — rule matching
    // compares against that form.
    ASSERT_TRUE(!self.name.empty());
    ASSERT_TRUE(self.name.find(L'\\') == std::wstring::npos);

    // A PID that cannot exist yields "leave it alone", never a partial entry.
    clew::live_process_info bogus;
    ASSERT_FALSE(clew::query_live_process(0xFFFFFFF0u, bogus));
}

TEST(sync_resolve_late_etw_start_is_idempotent) {
    // The fallback inserts using the process's real PSN, so the ETW START that
    // lands ~1.5s later carries the same (pid, psn) and must be a no-op. With a
    // synthesized PSN, add_entry would read that START as PID reuse, tombstone
    // the entry the fallback just classified and silently drop its proxy state.
    flat_tree tree;
    FILETIME ft{};
    const uint64_t real_psn = 4242;

    uint32_t idx = tree.add_entry(1000, 0, real_psn, ROOT_PSN_SENTINEL, ft, L"git.exe");
    tree.mark_root(idx);
    tree.at(idx).group_id = 7;
    tree.at(idx).set_flag(clew::entry_flags::AUTO_MATCHED);

    // Replay of the same identity, i.e. the delayed ETW START.
    uint32_t again = tree.add_entry(1000, 0, real_psn, ROOT_PSN_SENTINEL, ft, L"git.exe");
    ASSERT_EQ(again, idx);
    ASSERT_EQ(tree.at(idx).group_id, uint32_t{7});
    ASSERT_TRUE(tree.at(idx).has_flag(clew::entry_flags::AUTO_MATCHED));

    // Contrast: a different PSN under the same PID is genuine reuse, and there
    // the reset is the correct behavior.
    uint32_t reused = tree.add_entry(1000, 0, real_psn + 1, ROOT_PSN_SENTINEL, ft, L"git.exe");
    ASSERT_TRUE(reused != idx);
    ASSERT_EQ(tree.at(reused).group_id, NO_PROXY);
}

TEST(sync_resolve_chain_must_insert_top_down) {
    // resolve_pid_now collects unknown ancestors and inserts them parent-first.
    // The order is load-bearing, not cosmetic: inheritance tests the parent PID
    // against the rule's matched set, so a child inserted ahead of its parent
    // stays unmatched forever. This is exactly the git.exe -> git-remote-https
    // case, where both processes are younger than the ETW latency window.
    const AutoRule rule = make_rule("git_tree", "git.exe", /*hack_tree=*/true, /*group=*/5);
    FILETIME ft{};

    {   // Top-down: parent first, child inherits.
        rule_engine_v3 engine;
        engine.set_auto_rules({rule});
        flat_tree tree;

        uint32_t pidx = tree.add_entry(2000, 0, 1, ROOT_PSN_SENTINEL, ft, L"git.exe");
        tree.mark_root(pidx);
        engine.on_process_start(tree, pidx);

        uint32_t cidx = tree.add_entry(2001, 2000, 2, 1, ft, L"git-remote-https.exe");
        tree.attach_child(pidx, cidx);
        engine.on_process_start(tree, cidx);

        ASSERT_EQ(tree.at(pidx).group_id, uint32_t{5});
        ASSERT_EQ(tree.at(cidx).group_id, uint32_t{5});
    }

    {   // Bottom-up: child first, parent unknown -> no inheritance.
        rule_engine_v3 engine;
        engine.set_auto_rules({rule});
        flat_tree tree;

        uint32_t cidx = tree.add_entry(2001, 2000, 2, 1, ft, L"git-remote-https.exe");
        tree.mark_root(cidx);
        engine.on_process_start(tree, cidx);

        ASSERT_EQ(tree.at(cidx).group_id, NO_PROXY);
    }
}

// ============================================================
// Main runner
// ============================================================

int main() {
    // Initialize quill for test logging
    quill::Backend::start();
    auto sink = quill::Frontend::create_or_get_sink<quill::ConsoleSink>("test_console");
    clew::g_logger = quill::Frontend::create_or_get_logger("test", std::move(sink));
    clew::g_logger->set_log_level(quill::LogLevel::Info);

    std::cout << "============================================================\n";
    std::cout << "ProxyClaw Component Tests\n";
    std::cout << "============================================================\n\n";

    for (auto& [name, fn] : g_tests) {
        try {
            fn();
            g_pass++;
            std::cout << "  [PASS] " << name << "\n";
        } catch (const std::exception& e) {
            g_fail++;
            g_errors.push_back(name + ": " + e.what());
            std::cout << "  [FAIL] " << name << ": " << e.what() << "\n";
        }
    }

    std::cout << "\n============================================================\n";
    std::cout << "Results: " << g_pass << " passed, " << g_fail << " failed, "
              << (g_pass + g_fail) << " total\n";
    if (!g_errors.empty()) {
        std::cout << "\nFailures:\n";
        for (auto& e : g_errors) std::cout << "  - " << e << "\n";
    }
    std::cout << "============================================================\n";

    return g_fail == 0 ? 0 : 1;
}
