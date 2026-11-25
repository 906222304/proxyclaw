#pragma once

// DnsManager: orchestrates DNS forwarder lifecycle + system DNS configuration.
//
// Responsibilities:
// - Start/stop dns_forwarder based on config
// - Save original system DNS to dns_state.json on enable
// - Set system DNS to listen_host (default 127.0.0.2) on active interfaces
// - Restore system DNS on disable or clean shutdown
// - Recover from previous crash (dns_state.json exists at startup)
//
// Config changes go through request(): it returns at once and a dedicated
// worker thread runs apply() (the UDP ASSOCIATE / TCP probe can take up to
// ~13 s against a slow proxy). Requests that arrive while one is applied
// are coalesced; only the newest is applied next. status() reports
// off / starting / running / stopping / failed with a reason, and every
// change is pushed to the frontend as `dns_status`.

#define ASIO_STANDALONE
#include <asio.hpp>

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "config/types.hpp"
#include "core/dns_forwarder.hpp"
#include "core/system_dns.hpp"
#include "core/log.hpp"
#include "proxy/tcp_dns_upstream.hpp"
#include "transport/frontend_push_sink.hpp"

namespace clew {

// state: "off" | "starting" | "running" | "stopping" | "failed".
// error (failed only): "proxy_unreachable" (neither UDP ASSOCIATE nor a TCP
// CONNECT to the upstream worked), "no_interface", "backup_failed",
// "set_failed", "restore_failed", "mode_unsupported".
// recovery: "" (no prior crash file) | "recovered" | "failed".
struct DnsStatus {
    std::string state = "off";
    bool tcp_only = false;
    std::string error;
    std::string listen;
    std::string recovery;

    nlohmann::json to_json() const {
        nlohmann::json j{{"state", state}, {"tcp_only", tcp_only}};
        if (!error.empty()) j["error"] = error;
        if (!listen.empty()) j["listen"] = listen;
        if (!recovery.empty()) j["recovery"] = recovery;
        return j;
    }
    bool operator==(const DnsStatus&) const = default;
};

class DnsManager {
public:
    explicit DnsManager(asio::io_context& ioc,
                        std::filesystem::path state_file = "dns_state.json")
        : ioc_(ioc), state_file_(std::move(state_file)) {}

    ~DnsManager() noexcept {
        try { stop(); }
        catch (const std::exception& e) {
            PC_LOG_ERROR("[DNS-MGR] destructor caught: {}", e.what());
        } catch (...) {
            PC_LOG_ERROR("[DNS-MGR] destructor caught non-std exception");
        }
    }

    DnsManager(const DnsManager&) = delete;
    DnsManager& operator=(const DnsManager&) = delete;

    // Called once at startup before applying config: if a state file exists,
    // it means the previous session crashed while system DNS was modified.
    // Keep the backup if any interface cannot be restored yet.
    void recover_crash_state() {
        auto states = system_dns::load_state(state_file_);
        if (!states) return;
        PC_LOG_INFO("[DNS-MGR] Found dns_state.json from previous session, restoring...");
        saved_states_ = std::move(*states);
        system_dns_modified_ = !saved_states_.empty();
        restore_system_dns();
        const std::string outcome = system_dns_modified_ ? "failed" : "recovered";
        {
            std::lock_guard lk(status_mu_);
            recovery_ = outcome;
            status_.recovery = outcome;
        }
    }

    // Non-blocking apply: hand the config to the worker and return. Called
    // from the config observer (API thread) and at startup.
    void request(const DnsConfig& cfg, const std::string& proxy_host, uint16_t proxy_port) {
        // Cheap and lock-free for readers; TCP :53 must follow the config at once.
        publish_tcp_dns_upstream(cfg);
        const bool want = cfg.enabled && cfg.mode == "forwarder";
        {
            std::lock_guard lk(req_mu_);
            if (stopping_) return;
        }
        // Show progress before the worker can pick the request up, so its
        // final state is never overwritten by this one.
        auto st = status();
        if (want && st.state != "running") {
            set_status(DnsStatus{"starting", false, {}, cfg.listen_host, st.recovery});
        } else if (!want && (st.state == "running" || st.state == "starting")) {
            st.state = "stopping";
            set_status(std::move(st));
        }
        {
            std::lock_guard lk(req_mu_);
            if (stopping_) return;
            pending_ = request_t{cfg, proxy_host, proxy_port};
            if (!worker_.joinable())
                worker_ = std::thread([this] { worker_loop(); });
        }
        req_cv_.notify_one();
    }

    DnsStatus status() const {
        std::lock_guard lk(status_mu_);
        return status_;
    }

    // Push target for `dns_status` (the WebView2 host). Any thread.
    void set_sink(frontend_push_sink* sink) noexcept { sink_.store(sink); }
    void replay_to_frontend() {
        if (auto* sink = sink_.load()) sink->push("dns_status", status().to_json().dump());
    }

    // Apply new config synchronously (worker thread, or tests). Handles diff against current state:
    //   off → on:  start forwarder + set system DNS
    //   on → off:  stop forwarder + restore system DNS
    //   both on:   if upstream/listen changed → restore DNS, then restart
    void apply(const DnsConfig& cfg,
               const std::string& proxy_host, uint16_t proxy_port) {
        const bool want_enabled = cfg.enabled && cfg.mode == "forwarder";

        if (cfg.enabled && cfg.mode != "forwarder") {
            PC_LOG_WARN("[DNS-MGR] DNS mode '{}' not yet implemented (forwarder only)", cfg.mode);
        }

        if (!want_enabled) {
            // Keep the listener alive if an interface still points at it.
            if (!restore_system_dns()) {
                current_cfg_.enabled = false;
                fail("restore_failed", cfg);
                return;
            }
            stop_forwarder();
            current_cfg_ = cfg;
            current_cfg_.enabled = false;
            if (cfg.enabled) fail("mode_unsupported", cfg);
            else set_status(DnsStatus{});
            return;
        }

        // both on — check what changed
        const bool fwd_target_changed =
            current_cfg_.upstream_host != cfg.upstream_host ||
            current_cfg_.upstream_port != cfg.upstream_port ||
            current_cfg_.listen_host != cfg.listen_host ||
            current_cfg_.listen_port != cfg.listen_port ||
            current_proxy_host_ != proxy_host ||
            current_proxy_port_ != proxy_port;

        if (forwarder_ && current_cfg_.enabled && !fwd_target_changed) {
            current_cfg_ = cfg;
            set_running();
            return;
        }

        set_status(DnsStatus{"starting", false, {}, cfg.listen_host});
        // Restore first, so a failed restart cannot strand system DNS on a
        // dead listener or capture the old loopback address as the backup.
        if (!restore_system_dns()) {
            current_cfg_.enabled = false;
            fail("restore_failed", cfg);
            return;
        }
        stop_forwarder();
        current_cfg_ = cfg;
        current_cfg_.enabled = false;
        if (!start_forwarder(cfg, proxy_host, proxy_port)) {
            fail("proxy_unreachable", cfg);
            return;
        }
        if (const char* why = set_system_dns(cfg.listen_host)) {
            if (restore_system_dns()) stop_forwarder();
            fail(why, cfg);
            return;
        }
        current_cfg_.enabled = true;
        set_running();
    }

    // Clean shutdown: finish the request in progress (bounded by the SOCKS5
    // timeouts), drop the queued one, then restore system DNS, retaining the
    // backup on failure.
    void stop() {
        sink_.store(nullptr);
        {
            std::lock_guard lk(req_mu_);
            stopping_ = true;
            pending_.reset();
        }
        req_cv_.notify_one();
        if (worker_.joinable()) worker_.join();
        if (system_dns_modified_) {
            restore_system_dns();
        }
        stop_forwarder();
    }

private:
    struct request_t {
        DnsConfig cfg;
        std::string proxy_host;
        uint16_t proxy_port;
    };

    void worker_loop() {
        for (;;) {
            request_t r;
            {
                std::unique_lock lk(req_mu_);
                req_cv_.wait(lk, [this] { return stopping_ || pending_.has_value(); });
                if (stopping_) return;
                r = std::move(*pending_);
                pending_.reset();
            }
            try {
                apply(r.cfg, r.proxy_host, r.proxy_port);
            } catch (const std::exception& e) {
                PC_LOG_ERROR("[DNS-MGR] apply failed: {}", e.what());
                fail("proxy_unreachable", r.cfg);
            }
        }
    }

    void set_status(DnsStatus st) {
        {
            std::lock_guard lk(status_mu_);
            if (st.recovery.empty() && !recovery_.empty()) st.recovery = recovery_;
            if (status_ == st) return;
            status_ = st;
        }
        PC_LOG_INFO("[DNS-MGR] status {}{}", st.state, st.error.empty() ? "" : " (" + st.error + ")");
        if (auto* sink = sink_.load()) sink->push("dns_status", st.to_json().dump());
    }
    void set_running() {
        set_status(DnsStatus{"running", forwarder_ && forwarder_->tcp_only(), {},
                             current_cfg_.listen_host, {}});
    }
    void fail(const char* why, const DnsConfig& cfg) {
        set_status(DnsStatus{"failed", false, why, cfg.listen_host, {}});
    }

    std::mutex req_mu_;
    std::condition_variable req_cv_;
    std::optional<request_t> pending_;
    bool stopping_ = false;
    std::thread worker_;
    mutable std::mutex status_mu_;
    DnsStatus status_;
    std::string recovery_;
    std::atomic<frontend_push_sink*> sink_{nullptr};

    // Proxied TCP :53 goes to the configured upstream (proxy/tcp_dns_upstream.hpp).
    void publish_tcp_dns_upstream(const DnsConfig& cfg) {
        const auto ep = tcp_dns::resolve(cfg.upstream_host, cfg.upstream_port);
        const auto prev = tcp_dns::current();
        tcp_dns::publish(ep);
        if (prev.ip == ep.ip && prev.port == ep.port && tcp_dns_logged_) return;
        tcp_dns_logged_ = true;
        if (ep.fallback) {
            PC_LOG_WARN("[DNS-MGR] dns.upstream_host '{}' is not a usable IPv4 address; "
                        "proxied TCP:53 goes to 8.8.8.8:53", cfg.upstream_host);
        } else {
            PC_LOG_INFO("[DNS-MGR] Proxied TCP:53 -> {}:{}", cfg.upstream_host, ep.port);
        }
    }
    bool tcp_dns_logged_ = false;

    asio::io_context& ioc_;
    std::filesystem::path state_file_;
    std::unique_ptr<dns_forwarder> forwarder_;
    DnsConfig current_cfg_{};
    std::string current_proxy_host_;
    uint16_t current_proxy_port_ = 0;
    bool system_dns_modified_ = false;
    std::vector<system_dns::InterfaceDnsState> saved_states_;

    bool start_forwarder(const DnsConfig& cfg,
                         const std::string& proxy_host, uint16_t proxy_port) {
        forwarder_ = std::make_unique<dns_forwarder>(
            ioc_, cfg.listen_host, cfg.listen_port,
            proxy_host, proxy_port,
            cfg.upstream_host, cfg.upstream_port);
        if (forwarder_->start()) {
            PC_LOG_INFO("[DNS-MGR] Forwarder started{}: {}:{} -> SOCKS5 {}:{} -> {}:{}",
                         forwarder_->tcp_only() ? " (TCP only)" : "",
                         cfg.listen_host, cfg.listen_port,
                         proxy_host, proxy_port,
                         cfg.upstream_host, cfg.upstream_port);
            current_proxy_host_ = proxy_host;
            current_proxy_port_ = proxy_port;
            return true;
        } else {
            PC_LOG_WARN("[DNS-MGR] Forwarder failed to start");
            forwarder_->stop();
            forwarder_.reset();
            return false;
        }
    }

    void stop_forwarder() {
        if (forwarder_) {
            forwarder_->stop();
            forwarder_.reset();
            PC_LOG_INFO("[DNS-MGR] Forwarder stopped");
        }
    }

    // nullptr on success, else the failure reason for DnsStatus::error.
    const char* set_system_dns(const std::string& listen_host) {
        auto interfaces = system_dns::enumerate_active_interfaces();
        if (interfaces.empty()) {
            PC_LOG_WARN("[DNS-MGR] No active IPv4 interfaces found, skip system DNS");
            return "no_interface";
        }

        // Do not modify any interface unless crash recovery is available.
        if (!system_dns::save_state(state_file_, interfaces)) {
            PC_LOG_WARN("[DNS-MGR] Failed to save original DNS; leaving system DNS unchanged");
            return "backup_failed";
        }

        bool all_ok = true;
        for (const auto& st : interfaces) {
            if (system_dns::set_interface_dns(st.adapter_guid, {listen_host})) {
                saved_states_.push_back(st);
                PC_LOG_INFO("[DNS-MGR] Set DNS {} on {} (had: {} servers)",
                             listen_host, st.friendly_name, st.dns_servers.size());
            } else {
                all_ok = false;
                break;
            }
        }
        system_dns_modified_ = !saved_states_.empty();
        if (!system_dns_modified_) {
            // Nothing succeeded; no point keeping state file
            system_dns::delete_state(state_file_);
            saved_states_.clear();
        }
        return all_ok ? nullptr : "set_failed";
    }

    bool restore_system_dns() {
        if (saved_states_.empty()) return true;
        std::vector<system_dns::InterfaceDnsState> failed;
        for (const auto& st : saved_states_) {
            if (system_dns::restore_interface_dns(st)) {
                PC_LOG_INFO("[DNS-MGR] Restored DNS on {}: mode={} servers={}",
                             st.friendly_name, st.automatic ? "automatic" : "manual",
                             st.dns_servers.size());
            } else {
                failed.push_back(st);
            }
        }
        if (!failed.empty()) {
            saved_states_ = std::move(failed);
            system_dns_modified_ = true;
            PC_LOG_WARN("[DNS-MGR] DNS restore incomplete; keeping backup for retry");
            return false;
        }
        system_dns::delete_state(state_file_);
        saved_states_.clear();
        system_dns_modified_ = false;
        return true;
    }
};

} // namespace clew
