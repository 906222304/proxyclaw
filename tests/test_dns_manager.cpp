// Compile the production manager against controlled network/Windows adapters.
// These tests never open sockets or change the machine's DNS settings.
#include "core/dns_manager.hpp"
#include <iostream>
#include <stdexcept>
#include <utility>

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
    mgr.apply(enabled(), "127.0.0.1", 7890);
    CHECK(fwd::starts == 0);
    CHECK(dns::backup->at(0).dns_servers == std::vector<std::string>{"192.168.50.1"});
    dns::restore_failures.clear(); mgr.apply(enabled(), "127.0.0.1", 7890);
    proxy_dns(); CHECK(fwd::starts == 1);
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
