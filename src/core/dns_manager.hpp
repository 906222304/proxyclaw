#pragma once

// DnsManager: orchestrates DNS forwarder lifecycle + system DNS configuration.
//
// Responsibilities:
// - Start/stop dns_forwarder based on config
// - Save original system DNS to dns_state.json on enable
// - Set system DNS to listen_host (default 127.0.0.2) on active interfaces
// - Restore system DNS on disable or clean shutdown
// - Recover from previous crash (dns_state.json exists at startup)

#define ASIO_STANDALONE
#include <asio.hpp>

#include <memory>
#include <string>
#include <filesystem>

#include "config/types.hpp"
#include "core/dns_forwarder.hpp"
#include "core/system_dns.hpp"
#include "core/log.hpp"

namespace clew {

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
    }

    // Apply new config. Handles diff against current state:
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
                return;
            }
            stop_forwarder();
            current_cfg_ = cfg;
            current_cfg_.enabled = false;
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
            return;
        }

        // Restore first, so a failed restart cannot strand system DNS on a
        // dead listener or capture the old loopback address as the backup.
        if (!restore_system_dns()) {
            current_cfg_.enabled = false;
            return;
        }
        stop_forwarder();
        current_cfg_ = cfg;
        current_cfg_.enabled = false;
        if (!start_forwarder(cfg, proxy_host, proxy_port)) return;
        if (!set_system_dns(cfg.listen_host)) {
            if (restore_system_dns()) stop_forwarder();
            return;
        }
        current_cfg_.enabled = true;
    }

    // Clean shutdown: restore system DNS, retaining the backup on failure.
    void stop() {
        if (system_dns_modified_) {
            restore_system_dns();
        }
        stop_forwarder();
    }

private:
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
            PC_LOG_INFO("[DNS-MGR] Forwarder started: {}:{} -> SOCKS5 {}:{} -> {}:{}",
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

    bool set_system_dns(const std::string& listen_host) {
        auto interfaces = system_dns::enumerate_active_interfaces();
        if (interfaces.empty()) {
            PC_LOG_WARN("[DNS-MGR] No active IPv4 interfaces found, skip system DNS");
            return false;
        }

        // Do not modify any interface unless crash recovery is available.
        if (!system_dns::save_state(state_file_, interfaces)) {
            PC_LOG_WARN("[DNS-MGR] Failed to save original DNS; leaving system DNS unchanged");
            return false;
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
        return all_ok;
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
