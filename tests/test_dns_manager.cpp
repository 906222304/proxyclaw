// Compile the production manager against controlled network/Windows adapters.
// These tests never open sockets or change the machine's DNS settings.
#include "core/dns_manager.hpp"
#include <chrono>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

using clew::DnsManager;
using clew::DnsConfig;
namespace dns = clew::system_dns::fake;
namespace fwd = clew::fake_forwarder;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error(#expr); } while (false)

static void reset() { dns::reset(); fwd::reset(); }
static DnsConfig enabled() { DnsConfig cfg; cfg.enabled = true; return cfg; }
static void original_dns() {
    CHECK(dns::current.at("eth") == std::vector<std::string>{"192.168.50.1"});
    CHECK(dns::current.at("wifi") == std::vector<std::string>{"10.1.2.1"});
}
static void proxy_dns(const std::string& address = "127.0.0.2") {
    CHECK(dns::current.at("eth") == std::vector<std::string>{address});
    CHECK(dns::current.at("wifi") == std::vector<std::string>{address});
}

static void failed_start_does_not_change_dns() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    fwd::start_ok = false;
    mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(dns::sets == 0); CHECK(!dns::backup); CHECK(fwd::active == 0);
    original_dns();
}
static void same_config_retries_failed_start() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    fwd::start_ok = false; mgr.apply(enabled(), "127.0.0.1", 7890);
    fwd::start_ok = true; mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(fwd::starts == 2); CHECK(fwd::active == 1); CHECK(dns::backup);
    proxy_dns();
}
static void backup_failure_does_not_change_dns() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    dns::save_ok = false; mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(dns::sets == 0); CHECK(fwd::active == 0); original_dns();
}
static void partial_set_failure_rolls_back() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    dns::set_failures.insert("wifi");
    mgr.apply(enabled(), "127.0.0.1", 7890);
    original_dns(); CHECK(!dns::backup); CHECK(fwd::active == 0);
    dns::set_failures.clear(); mgr.apply(enabled(), "127.0.0.1", 7890);
    proxy_dns(); CHECK(fwd::active == 1);
}
static void failed_restart_restores_original_dns() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890);
    auto cfg = enabled(); cfg.upstream_host = "1.1.1.1";
    fwd::start_ok = false; mgr.apply(cfg, "127.0.0.1", 7890);
    original_dns(); CHECK(!dns::backup); CHECK(fwd::active == 0);
    fwd::start_ok = true; mgr.apply(cfg, "127.0.0.1", 7890);
    proxy_dns(); CHECK(fwd::starts == 3);
}
static void failed_partial_rollback_keeps_listener() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    dns::set_failures.insert("wifi"); dns::restore_failures.insert("eth");
    mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(fwd::active == 1); CHECK(dns::backup);
    CHECK(dns::current.at("eth") == std::vector<std::string>{"127.0.0.2"});
    dns::set_failures.clear(); dns::restore_failures.clear();
    mgr.apply(enabled(), "127.0.0.1", 7890);
    proxy_dns(); CHECK(fwd::starts == 2);
}
static void failed_restore_keeps_old_listener() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890);
    dns::restore_failures.insert("eth");
    auto cfg = enabled(); cfg.listen_host = "127.0.0.3";
    mgr.apply(cfg, "127.0.0.1", 7890);
    CHECK(fwd::active == 1); CHECK(fwd::starts == 1); CHECK(dns::backup);
    CHECK(dns::current.at("eth") == std::vector<std::string>{"127.0.0.2"});
    dns::restore_failures.clear(); mgr.apply(cfg, "127.0.0.1", 7890);
    proxy_dns("127.0.0.3"); CHECK(fwd::starts == 2);
}
static void listener_change_preserves_original_backup() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890);
    auto cfg = enabled(); cfg.listen_host = "127.0.0.3";
    mgr.apply(cfg, "127.0.0.1", 7890);
    proxy_dns("127.0.0.3"); CHECK(dns::backup);
    CHECK(dns::backup->at(0).dns_servers == std::vector<std::string>{"192.168.50.1"});
    mgr.stop(); original_dns(); CHECK(!dns::backup);
}
static void disable_failure_can_be_retried() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890);
    dns::restore_failures.insert("eth"); mgr.apply(DnsConfig{}, "127.0.0.1", 7890);
    CHECK(dns::backup); CHECK(fwd::active == 1);
    dns::restore_failures.clear(); mgr.apply(DnsConfig{}, "127.0.0.1", 7890);
    original_dns(); CHECK(!dns::backup); CHECK(fwd::active == 0);
}
static void shutdown_failure_keeps_recovery_file() {
    reset(); asio::io_context ioc;
    {
        DnsManager mgr(ioc); mgr.apply(enabled(), "127.0.0.1", 7890);
        dns::restore_failures.insert("eth"); mgr.stop();
        CHECK(dns::backup); CHECK(fwd::active == 0);
    }
    CHECK(dns::backup);
    dns::restore_failures.clear(); DnsManager next(ioc); next.recover_crash_state();
    original_dns(); CHECK(!dns::backup);
}
static void reenable_after_failed_disable_reconfigures_all_interfaces() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890);
    dns::restore_failures.insert("eth"); mgr.apply(DnsConfig{}, "127.0.0.1", 7890);
    dns::restore_failures.clear(); mgr.apply(enabled(), "127.0.0.1", 7890);
    proxy_dns(); CHECK(fwd::starts == 2);
}
static void crash_restore_failure_blocks_replacement_backup() {
    reset(); asio::io_context ioc;
    dns::backup = dns::interfaces;
    dns::current["eth"] = {"127.0.0.2"}; dns::current["wifi"] = {"127.0.0.2"};
    dns::restore_failures.insert("eth"); DnsManager mgr(ioc);
    mgr.recover_crash_state(); CHECK(dns::backup);
    CHECK(mgr.status().recovery == "failed");
    mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(fwd::starts == 0);
    CHECK(dns::backup->at(0).dns_servers == std::vector<std::string>{"192.168.50.1"});
    dns::restore_failures.clear(); mgr.apply(enabled(), "127.0.0.1", 7890);
    proxy_dns(); CHECK(fwd::starts == 1);

    // Clean recovery marks recovery == "recovered".
    reset();
    dns::backup = dns::interfaces;
    dns::current["eth"] = {"127.0.0.2"}; dns::current["wifi"] = {"127.0.0.2"};
    DnsManager mgr2(ioc);
    mgr2.recover_crash_state();
    CHECK(!dns::backup);
    CHECK(mgr2.status().recovery == "recovered");
}
static void unchanged_config_does_not_restart() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890); mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(fwd::starts == 1); CHECK(dns::sets == 2); proxy_dns();
}
static void no_interfaces_stops_listener() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc); dns::interfaces.clear();
    mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(fwd::active == 0); CHECK(dns::sets == 0); CHECK(!dns::backup);
}
static void unsupported_mode_does_not_enable() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    auto cfg = enabled(); cfg.mode = "unknown"; mgr.apply(cfg, "127.0.0.1", 7890);
    CHECK(fwd::starts == 0); CHECK(dns::sets == 0); original_dns();
}

// --- request(): background apply + status ---
using namespace std::chrono_literals;
struct recording_sink : clew::frontend_push_sink {
    std::mutex mu;
    std::vector<std::string> events;
    void push(std::string_view event, std::string body) override {
        std::lock_guard lk(mu);
        events.push_back(std::string(event) + " " + body);
    }
    std::vector<std::string> get() { std::lock_guard lk(mu); return events; }
};
static clew::DnsStatus wait_state(DnsManager& mgr, const std::string& state) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
        auto st = mgr.status();
        if (st.state == state) return st;
        std::this_thread::sleep_for(5ms);
    }
    throw std::runtime_error("status never became " + state + " (is " + mgr.status().state + ")");
}
static void request_returns_before_start_finishes() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    recording_sink sink; mgr.set_sink(&sink);
    fwd::start_delay_ms = 300;
    const auto t0 = std::chrono::steady_clock::now();
    mgr.request(enabled(), "127.0.0.1", 7890);
    CHECK(std::chrono::steady_clock::now() - t0 < 100ms);
    CHECK(mgr.status().state == "starting");
    auto st = wait_state(mgr, "running");
    CHECK(!st.tcp_only); CHECK(st.listen == "127.0.0.2");
    proxy_dns();
    auto ev = sink.get();
    CHECK(ev.size() == 2);
    CHECK(ev[0].find("\"starting\"") != std::string::npos);
    CHECK(ev[1].find("\"running\"") != std::string::npos);
    mgr.stop(); original_dns();
}
static void request_reports_failure_reason() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    fwd::start_ok = false; mgr.request(enabled(), "127.0.0.1", 7890);
    CHECK(wait_state(mgr, "failed").error == "proxy_unreachable");
    fwd::start_ok = true; dns::save_ok = false; mgr.request(enabled(), "127.0.0.1", 7890);
    CHECK(wait_state(mgr, "failed").error == "backup_failed");
    dns::save_ok = true; dns::interfaces.clear(); mgr.request(enabled(), "127.0.0.1", 7890);
    CHECK(wait_state(mgr, "failed").error == "no_interface");
    original_dns();
}
static void request_reports_tcp_only_and_off() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    fwd::tcp_only = true; mgr.request(enabled(), "127.0.0.1", 7890);
    CHECK(wait_state(mgr, "running").tcp_only);
    mgr.request(DnsConfig{}, "127.0.0.1", 7890);
    wait_state(mgr, "off"); original_dns(); CHECK(fwd::active == 0);
}
static void queued_requests_are_coalesced() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    fwd::start_delay_ms = 200;
    mgr.request(enabled(), "127.0.0.1", 7890);
    std::this_thread::sleep_for(50ms);  // first one is being applied
    auto a = enabled(); a.upstream_host = "1.1.1.1"; mgr.request(a, "127.0.0.1", 7890);
    auto b = enabled(); b.upstream_host = "9.9.9.9"; mgr.request(b, "127.0.0.1", 7890);
    std::this_thread::sleep_for(50ms);
    wait_state(mgr, "running");
    std::this_thread::sleep_for(300ms);  // let any (wrongly) queued apply run
    wait_state(mgr, "running");
    CHECK(fwd::starts == 2);  // first + newest; the middle one was dropped
}
static void stop_waits_for_start_and_restores() {
    reset(); asio::io_context ioc;
    {
        DnsManager mgr(ioc);
        fwd::start_delay_ms = 200;
        mgr.request(enabled(), "127.0.0.1", 7890);
        std::this_thread::sleep_for(50ms);
        mgr.stop();
        CHECK(fwd::active == 0); original_dns(); CHECK(!dns::backup);
        mgr.request(enabled(), "127.0.0.1", 7890);  // ignored after stop
    }
    CHECK(fwd::starts == 1);
}
static void proxy_credentials_change_restarts_forwarder() {
    reset(); asio::io_context ioc; DnsManager mgr(ioc);
    mgr.apply(enabled(), "127.0.0.1", 7890, {"alice", "pw1"});
    CHECK(fwd::starts == 1 && fwd::last_creds.user == "alice" && fwd::last_creds.password == "pw1");
    mgr.apply(enabled(), "127.0.0.1", 7890, {"alice", "pw1"});
    CHECK(fwd::starts == 1);  // unchanged creds do not restart
    mgr.apply(enabled(), "127.0.0.1", 7890, {"alice", "pw2"});
    CHECK(fwd::starts == 2 && fwd::last_creds.password == "pw2");
}

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"failed start leaves DNS unchanged", failed_start_does_not_change_dns},
        {"same config retries failed start", same_config_retries_failed_start},
        {"backup failure leaves DNS unchanged", backup_failure_does_not_change_dns},
        {"partial set failure rolls back", partial_set_failure_rolls_back},
        {"failed restart restores DNS", failed_restart_restores_original_dns},
        {"failed rollback keeps listener", failed_partial_rollback_keeps_listener},
        {"failed restore keeps old listener", failed_restore_keeps_old_listener},
        {"listener change preserves original backup", listener_change_preserves_original_backup},
        {"disable failure is retried", disable_failure_can_be_retried},
        {"shutdown failure keeps recovery file", shutdown_failure_keeps_recovery_file},
        {"re-enable after failed disable configures all interfaces", reenable_after_failed_disable_reconfigures_all_interfaces},
        {"crash recovery failure blocks new backup", crash_restore_failure_blocks_replacement_backup},
        {"unchanged config does not restart", unchanged_config_does_not_restart},
        {"no interfaces stops listener", no_interfaces_stops_listener},
        {"unsupported mode stays disabled", unsupported_mode_does_not_enable},
        {"request returns before start finishes", request_returns_before_start_finishes},
        {"request reports failure reason", request_reports_failure_reason},
        {"request reports TCP-only and off", request_reports_tcp_only_and_off},
        {"queued requests are coalesced", queued_requests_are_coalesced},
        {"stop waits for start and restores", stop_waits_for_start_and_restores},
        {"proxy credentials change restarts forwarder", proxy_credentials_change_restarts_forwarder},
    };
    int failures = 0;
    for (const auto& [name, test] : cases) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) {
            ++failures; std::cerr << "FAIL " << name << ": " << e.what() << '\n';
        }
    }
    return failures ? 1 : 0;
}
