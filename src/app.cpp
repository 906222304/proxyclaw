#include "app.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "common/api_exception.hpp"
#include "common/dev_hooks.hpp"
#include "config/config_change_tag.hpp"
#include "config/types.hpp"
#include "core/exe_paths.hpp"
#include "core/log.hpp"
#include "services/autostart_service.hpp"

namespace clew {

namespace {

bool pump_pending_messages() {
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) {
            PostQuitMessage(static_cast<int>(msg.wParam));
            return false;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return true;
}

// Console fallback (no WebView2 window): Ctrl+C / console close ends the
// main loop. The handler runs on a system thread; for close / logoff /
// shutdown Windows terminates the process as soon as it returns, so it waits
// (bounded) for shutdown() to restore DNS and close the WinDivert handles.
HANDLE g_console_stop = nullptr;  // manual-reset: stop requested
HANDLE g_console_done = nullptr;  // manual-reset: shutdown() finished

BOOL WINAPI console_ctrl_handler(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            if (g_console_stop) SetEvent(g_console_stop);
            return TRUE;
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            if (g_console_stop) SetEvent(g_console_stop);
            if (g_console_done) WaitForSingleObject(g_console_done, 4500);
            return TRUE;
        default:
            return FALSE;
    }
}

std::wstring utf8_to_wide(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

} // namespace

app::app(const cli_options& opts, HINSTANCE hinstance)
    : opts_(opts)
    , hinstance_(hinstance)
    , config_(opts.config_path.empty()
              ? exe_relative("proxyclaw.json")
              : std::filesystem::path{opts.config_path})
    , strand_(asio::make_strand(ioc_))
    , cfg_store_(config_)
    , tree_mgr_(ioc_, strand_)
    , exec_(tree_mgr_, strand_)
    , dns_mgr_(ioc_, exe_relative("dns_state.json"))
    , acceptor_(ioc_, *port_tracker_, strand_, tcp_groups_)
    , acceptor_v6_(ioc_, *port_tracker_, strand_, tcp_groups_, &v6_flows_)
    , socks5_udp_mgr_(ioc_, {})
    , projection_(tree_mgr_, strand_)
    , cfg_bridge_(cfg_store_)
    , config_svc_(cfg_store_)
    , connection_svc_(exec_, udp_port_tracker_.get(), &udp_session_table_, decision_log_.get())
    , group_svc_(exec_, cfg_store_)
    , icon_svc_(icons_)
    , process_svc_(exec_)
    , rule_svc_(exec_, cfg_store_)
    , stats_svc_(exec_, [this]() { return traffic_stats(); })
    , ctx_{
        .config      = config_svc_,
        .connections = connection_svc_,
        .groups      = group_svc_,
        .icons       = icon_svc_,
        .processes   = process_svc_,
        .rules       = rule_svc_,
        .stats       = stats_svc_,
      }
    , api_server_(API_PORT, ctx_, opts_.static_dir)
{
    if (!config_.load()) {
        throw std::runtime_error("ProxyClaw configuration could not be loaded or saved");
    }
    set_log_level(config_.get_v2().log_level);

    num_workers_ = config_.get_v2().io_threads;
    if (num_workers_ <= 0) {
        num_workers_ = std::max(2u, std::thread::hardware_concurrency() / 2);
    }
    PC_LOG_INFO("io_context with {} worker threads", num_workers_);

    tree_mgr_.rules().set_auto_rules(config_.get_v2().auto_rules);
    tree_mgr_.rules().set_default_exclude_cidrs(config_.get_v2().default_exclude_cidrs);
    policy_pub_.publish(tree_mgr_.rules().build_policy_table());
    PC_LOG_INFO("Loaded {} auto rules", config_.get_v2().auto_rules.size());

    sync_groups();
    dns_mgr_.recover_crash_state();

    redirect_port_ = acceptor_.start();
    PC_LOG_INFO("Acceptor listening on port {}", redirect_port_);
    redirect_port_v6_ = acceptor_v6_.start();

    // SYN parking (kill switch: tcp_syn_parking.enabled). Off means no pool,
    // no injector thread, and both TCP layers fall back to the pre-parking
    // code paths — it must bypass the new code entirely, because it is the
    // one thing left when the new code is what broke.
    {
        const auto& sp = config_.get_v2().tcp_syn_parking;
        if (sp.enabled) {
            parker_ = std::make_unique<syn_parker>(*port_tracker_, sp.watchdog_ms,
                                                   static_cast<uint32_t>(std::max(0, sp.pool_size)));
            parker_->set_decision_log(decision_log_.get());
            PC_LOG_INFO("[SYN-PARK] enabled: watchdog={}ms pool={}",
                        parker_->watchdog_ms(), parker_->pool_size());
        } else {
            PC_LOG_WARN("[SYN-PARK] disabled by config (tcp_syn_parking.enabled=false): "
                        "a process's first connection may escape interception");
        }
    }

    // Both SOCKET layers run on the same strand as the tree manager, so the
    // fallback resolve is a plain in-line call — no marshalling needed.
    auto resolve_unknown_pid = [this](DWORD pid) { return tree_mgr_.resolve_pid_now(pid); };

    wd_socket_      = std::make_unique<windivert_socket>(ioc_, strand_, tree_mgr_.tree(),
                                                         tree_mgr_.rules(), *port_tracker_,
                                                         resolve_unknown_pid, parker_.get(),
                                                         decision_log_.get());
    wd_network_     = std::make_unique<windivert_network>(*port_tracker_, redirect_port_,
                                                          parker_.get());
    ipv6_block_.store(ipv6_blocks(config_.get_v2().ipv6));
    ipv6_proxy_.store(ipv6_proxies(config_.get_v2().ipv6) && redirect_port_v6_ != 0);
    wd_network_v6_  = std::make_unique<windivert_network_v6>(v6_flows_, redirect_port_v6_);
    wd_socket_->set_ipv6(&ipv6_block_, &ipv6_proxy_,
                         [this](uint16_t port, v6_verdict v, const v6_flow* flow) {
        // Publish (or forget) the flow before the verdict releases parked SYNs.
        if (v == v6_verdict::proxy && flow) v6_flows_.publish(port, *flow);
        else if (v != v6_verdict::none)     v6_flows_.erase(port);
        if (wd_network_v6_) wd_network_v6_->on_decided(port, v);
    });
    PC_LOG_INFO("IPv6 mode: {}", ipv6_mode_name());
    wd_socket_udp_  = std::make_unique<windivert_socket_udp>(ioc_, strand_, tree_mgr_.tree(),
                                                              tree_mgr_.rules(), *udp_port_tracker_,
                                                              resolve_unknown_pid);
    wd_socket_udp_->set_decision_log(decision_log_.get());
    wd_socket_udp_->set_ipv6_block(&ipv6_block_);
    {
        const auto& up = config_.get_v2().udp_first_packet;
        const auto park_ms = up.enabled ? std::clamp(up.watchdog_ms, 5, 50) : 0;
        if (!up.enabled)
            PC_LOG_WARN("[WD-NET-UDP] first-packet parking disabled by config "
                        "(udp_first_packet.enabled=false)");
        wd_network_udp_ = std::make_unique<windivert_network_udp>(
            *udp_port_tracker_, udp_session_table_, policy_pub_, std::chrono::milliseconds{park_ms});
        wd_network_udp_->set_decision_log(decision_log_.get());
        wd_network_udp_->set_ipv6_block(&ipv6_block_);
    }
    wd_socket_udp_->set_decision_listener([this](uint16_t port) {
        if (wd_network_udp_) wd_network_udp_->release(port);
    });

    icons_.init();

    tree_mgr_.add_listener(&projection_);

    wire_observers();

    gui_ = create_gui();

    // Wire backend->frontend push channel. The WebView2 host implements the
    // sink; setting it on projection / cfg_bridge enables broadcast. The
    // ready-handshake callback runs on the UI thread; replay_to_frontend
    // reads the atomic snapshot (no strand needed) and pushes back through
    // the same WM_PUSH_TO_FRONTEND marshalling path.
    if (gui_) {
        projection_.set_sink(gui_.get());
        cfg_bridge_.set_sink(gui_.get());
        gui_->set_on_ready([this]() {
            projection_.replay_to_frontend();
        });
        // Visibility hand-off. Host transitions IsVisible on minimize /
        // restore / tray hide / tray show; projection drops on_tree_changed
        // work while hidden; the visible transition triggers a fresh replay.
        gui_->set_on_visibility_change([this](bool v) {
            projection_.set_frontend_visible(v);
        });
        projection_.set_frontend_visible(gui_->is_visible());
    }
}

app::~app() noexcept {
    shutdown();
}

int app::run() {
    start_servers_and_workers();
    wait_for_tree_init();
    start_traffic_layers();
    PC_LOG_INFO("ProxyClaw is ready.");
    // An elevated logon task that launches an exe from a folder non-admins can
    // modify is a silent elevation path. Report it (log + the settings page,
    // which reads the same state from /api/autostart) instead of keeping it
    // quietly. Off the main thread: schtasks takes a moment.
    autostart_check_ = std::jthread([]() {
        try {
            const auto s = autostart_service::query();
            if (s.enabled && !s.task_trusted) {
                PC_LOG_WARN("autostart: the ProxyClawAutoStart task is UNSAFE and should be "
                            "turned off or re-created from a protected folder: {}", s.task_issue);
            } else if (s.enabled && !s.task_matches_exe) {
                PC_LOG_WARN("autostart: the ProxyClawAutoStart task launches a different exe ({})",
                            s.task_command);
            }
        } catch (const std::exception& e) {
            PC_LOG_WARN("autostart: startup check failed: {}", e.what());
        }
    });
    int rc = run_main_loop();
    shutdown();
    return rc;
}

void app::sync_groups() {
    // Called from the config observer on whichever API worker ran the
    // mutation, possibly two at once. Serialise the rebuilds and always read
    // the *latest* config (not the observer's snapshot), so the last rebuild
    // to finish publishes the newest groups even if observers run out of
    // order. Relays read the TCP table as an immutable snapshot (pointer swap); the
    // UDP manager copies under its own mutex.
    std::scoped_lock lk(groups_sync_mu_);
    const ConfigV2 cfg = cfg_store_.get();
    ProxyGroupMap                                     tcp;
    std::unordered_map<uint32_t, UdpProxyGroupConfig> udp;
    for (const auto& g : cfg.proxy_groups) {
        tcp[g.id] = {g.host, g.port};
        udp[g.id] = {g.host, g.port};
    }
    const auto n = tcp.size();
    tcp_groups_.publish(std::move(tcp));
    socks5_udp_mgr_.set_groups(udp);
    PC_LOG_INFO("Proxy groups synced: {} groups", n);
}

nlohmann::json app::traffic_stats() const {
    nlohmann::json j;
    if (wd_socket_) {
        const auto s = wd_socket_->snapshot();
        j["socket"] = {
            {"connect_events",        s.connect_events},
            {"close_events",          s.close_events},
            {"proxied_decisions",     s.proxied_decisions},
            {"direct_decisions",      s.direct_decisions},
            {"self_direct",           s.self_direct},
            {"echo_ignored",          s.echo_ignored},
            {"late_rejected",         s.late_rejected},
            {"late_rejected_proxied", s.late_rejected_proxied},
            {"close_while_pending",   s.close_while_pending},
            {"ipv6_unmanaged",        s.ipv6_unmanaged},
            {"ipv6_blocked",          s.ipv6_blocked},
            {"ipv6_proxied",          s.ipv6_proxied},
        };
    }
    if (wd_socket_udp_) {
        j["udp_socket"] = {{"ipv6_unmanaged", wd_socket_udp_->ipv6_unmanaged_count()},
                           {"ipv6_blocked",
                            wd_network_udp_ ? wd_network_udp_->ipv6_blocked_count() : 0}};
    }
    j["ipv6"] = {{"mode", ipv6_mode_name()}, {"proxy_available", redirect_port_v6_ != 0},
                 {"flows", v6_flows_.size()}};
    if (wd_network_v6_) {
        j["ipv6"]["syn_proxied"]   = wd_network_v6_->proxied();
        j["ipv6"]["nat"]           = wd_network_v6_->nat_count();
        j["ipv6"]["syn_blocked"]   = wd_network_v6_->blocked();
        j["ipv6"]["syn_allowed"]   = wd_network_v6_->allowed();
        j["ipv6"]["syn_parked"]    = wd_network_v6_->parked();
        j["ipv6"]["syn_watchdog"]  = wd_network_v6_->released_by_watchdog();
    }
    if (decision_log_) {
        const auto d = decision_log_->snapshot();
        j["decisions"] = {{"written", d.written}, {"dropped", d.dropped}, {"capacity", d.capacity}};
    }
    if (parker_) {
        const auto c = parker_->snapshot();
        j["parking"] = {
            {"enabled",              true},
            {"watchdog_ms",          c.watchdog_ms},
            {"pool_size",            c.pool_size},
            {"hires_timer",          c.hires_timer},
            {"parked",               c.parked},
            {"released_by_decision", c.released_by_decision},
            {"released_by_watchdog", c.released_by_watchdog},
            {"released_by_drain",    c.released_by_drain},
            {"ttl_stale",            c.ttl_stale},
            {"retransmit_passed",    c.retransmit_passed},
            {"dup_syn_dropped",      c.dup_syn_dropped},
            {"cas_lost_to_decision", c.cas_lost_to_decision},
            {"pool_exhausted",       c.pool_exhausted},
            {"oversize",             c.oversize},
            {"gen_mismatch",         c.gen_mismatch},
            {"send_failures",        c.send_failures},
            {"pool_in_use",          c.pool_in_use},
            {"pool_peak",            c.pool_peak},
            {"park_us_max",          c.park_us_max},
            {"park_us_mean",         c.released_by_decision ? c.park_us_sum / c.released_by_decision : 0},
        };
    } else {
        j["parking"] = {{"enabled", false}};
    }
    return j;
}

std::pair<std::string, uint16_t> app::pick_proxy_endpoint(const ConfigV2& v2) {
    if (!v2.proxy_groups.empty()) {
        return {v2.proxy_groups[0].host, v2.proxy_groups[0].port};
    }
    return {v2.default_proxy.host, v2.default_proxy.port};
}

void app::wire_observers() {
    cfg_store_.subscribe(
        [this](const ConfigV2& cfg, config_change tag) {
            // Window geometry is UI-only state: nothing below depends on it.
            if (tag == config_change::ui_geometry) return;
            try {
                exec_.command([this, rules = cfg.auto_rules,
                               excludes = cfg.default_exclude_cidrs](domain::process_tree_manager& m) {
                    m.rules().set_default_exclude_cidrs(excludes);
                    m.apply_auto_rules_from_config(rules);
                    // Republish the exclude policy the UDP workers read. Rebuilt
                    // whole rather than patched: readers rely on the table being
                    // immutable once published.
                    policy_pub_.publish(m.rules().build_policy_table());
                });
            } catch (const api_exception& e) {
                PC_LOG_WARN("[config-sync] rule reload failed: {}", e.message());
            }
            sync_groups();
            set_log_level(cfg.log_level);
            {
                const bool was_block = ipv6_block_.exchange(ipv6_blocks(cfg.ipv6));
                const bool was_proxy = ipv6_proxy_.exchange(ipv6_proxies(cfg.ipv6) && redirect_port_v6_ != 0);
                if (was_block != ipv6_block_.load() || was_proxy != ipv6_proxy_.load())
                    PC_LOG_INFO("IPv6 mode: {}", ipv6_mode_name());
            }
            if (gui_) gui_->set_close_to_tray(cfg.ui.close_to_tray);
            auto [ph, pp] = pick_proxy_endpoint(cfg);
            dns_mgr_.apply(cfg.dns, ph, pp);
        });
}

std::unique_ptr<webview_app> app::create_gui() {
    if (!opts_.gui_mode) return nullptr;

    PC_LOG_INFO("Launching WebView2 GUI...");
    if (!is_webview2_available()) {
        PC_LOG_WARN("WebView2 not available, falling back to console mode");
        // Without the embedded host nothing can set the session cookie, so
        // print the one-time entry URL for a desktop browser.
        PC_LOG_WARN("Open the UI in a browser at http://127.0.0.1:{}{}",
                    API_PORT, api_server_.bootstrap_path());
        return nullptr;
    }

    const auto&  ui_cfg = config_.get_v2().ui;
    // PROXYCLAW_DEV_URL lets a developer point the embedded WebView2 at a Vite
    // dev server (e.g. http://localhost:5173) for HMR-driven frontend work.
    // Production builds always navigate to the embedded static files served
    // by the local HTTP API. WebView2 still provides PostWebMessageAsJson
    // regardless of which page is loaded.
    std::wstring url;
    // Honoured only with dev hooks enabled (debug build or --dev-hooks):
    // the URL receives the session token. See common/dev_hooks.hpp.
    if (const char* dev = dev_env("PROXYCLAW_DEV_URL")) {
        const int wlen = MultiByteToWideChar(CP_UTF8, 0, dev, -1, nullptr, 0);
        if (wlen > 0) {
            url.resize(static_cast<size_t>(wlen - 1));
            MultiByteToWideChar(CP_UTF8, 0, dev, -1, url.data(), wlen);
            PC_LOG_INFO("PROXYCLAW_DEV_URL set; loading dev frontend from {}", dev);
        }
    }
    if (url.empty()) {
        url = std::format(L"http://127.0.0.1:{}/", API_PORT);
    }
    // Enter through the session bootstrap so the API's HttpOnly cookie is set
    // before the UI loads. The dev server proxies /api, so the same path works
    // there. The resulting URL carries the token and must not be logged.
    {
        while (!url.empty() && url.back() == L'/') url.pop_back();
        const std::string boot = api_server_.bootstrap_path();
        url.append(boot.begin(), boot.end());
    }
    auto gui = std::make_unique<webview_app>(url, ui_cfg.window_width, ui_cfg.window_height);
    gui->set_title(L"ProxyClaw");
    gui->set_initial_rect(ui_cfg.window_x, ui_cfg.window_y,
                           ui_cfg.window_width, ui_cfg.window_height);
    gui->set_close_to_tray(ui_cfg.close_to_tray);
    gui->set_devtools_enabled(opts_.devtools);
    gui->set_start_minimized(opts_.start_minimized);
    // Runs on the UI thread. The save goes through config_store (same mutex
    // as every API mutation) and is debounced onto the saver thread, so a
    // burst of move/resize ends ~500 ms later as one write.
    gui->set_on_move_resize([this](int x, int y, int w, int h) {
        geometry_saver_.schedule([this, x, y, w, h]() { save_window_geometry(x, y, w, h); });
    });

    if (!gui->create(hinstance_)) {
        PC_LOG_ERROR("WebView2 window creation failed");
        return nullptr;
    }
    return gui;
}

void app::save_window_geometry(int x, int y, int w, int h) noexcept {
    try {
        if (const auto ui = cfg_store_.get().ui;
            ui.window_x == x && ui.window_y == y &&
            ui.window_width == w && ui.window_height == h) {
            return;  // nothing moved (e.g. a click on the title bar)
        }
        cfg_store_.mutate([&](ConfigV2& c) {
            c.ui.window_x      = x;
            c.ui.window_y      = y;
            c.ui.window_width  = w;
            c.ui.window_height = h;
        }, config_change::ui_geometry);
    } catch (const api_exception& e) {
        PC_LOG_WARN("[ui] saving window geometry failed: {}", e.message());
    } catch (const std::exception& e) {
        PC_LOG_WARN("[ui] saving window geometry failed: {}", e.what());
    }
}

void app::start_servers_and_workers() {
    if (!api_server_.start()) {
        throw startup_error{"Failed to start HTTP API server"};
    }
    PC_LOG_INFO("HTTP API: http://127.0.0.1:{}/", API_PORT);

    {
        const ConfigV2 cfg = cfg_store_.get();
        auto [ph, pp] = pick_proxy_endpoint(cfg);
        dns_mgr_.apply(cfg.dns, ph, pp);
    }

    tree_mgr_.start();

    workers_.reserve(static_cast<size_t>(num_workers_));
    for (int i = 0; i < num_workers_; ++i) {
        workers_.emplace_back([this]() { ioc_.run(); });
    }
}

void app::wait_for_tree_init() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!tree_mgr_.is_initialized() && !init_interrupted_ &&
           std::chrono::steady_clock::now() < deadline) {
        if (gui_ && !pump_pending_messages()) {
            init_interrupted_ = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!tree_mgr_.is_initialized() && !init_interrupted_) {
        PC_LOG_ERROR("Tree initialization timeout");
    }
}

void app::start_traffic_layers() {
    if (!tree_mgr_.is_initialized()) return;

    // Initial auto-rule scan + notify. apply_auto_rules_from_config re-applies
    // the same list already loaded above, but routes through manager's
    // notify_tree_changed() so projection refreshes its snapshot.
    asio::post(strand_, [this]() {
        auto rules_copy = tree_mgr_.rules().auto_rules();
        tree_mgr_.apply_auto_rules_from_config(rules_copy);
        PC_LOG_INFO("Initial auto-rule scan complete");
    });

    if (wd_socket_->open()) {
        wd_socket_->start();
        PC_LOG_INFO("WinDivert SOCKET layer started");
    } else {
        PC_LOG_ERROR("WinDivert SOCKET layer failed — traffic interception disabled");
    }

    if (wd_network_->open()) {
        // The injector sends through the NETWORK handle; it must be running
        // before the workers can park anything.
        if (parker_) parker_->start(wd_network_->handle(), redirect_port_);
        wd_network_->start(2);
        PC_LOG_INFO("WinDivert NETWORK layer started ({} workers)", 2);
    } else {
        PC_LOG_ERROR("WinDivert NETWORK layer failed — traffic interception disabled");
    }

    if (wd_network_v6_->open()) {
        wd_network_v6_->start();
        PC_LOG_INFO("WinDivert IPv6 TCP layer started (acceptor port {})", redirect_port_v6_);
    } else {
        PC_LOG_ERROR("WinDivert IPv6 TCP layer failed — IPv6 of proxied processes is not blocked or proxied");
    }

    if (wd_socket_udp_->open()) {
        wd_socket_udp_->start();
        PC_LOG_INFO("WinDivert UDP SOCKET layer started");
    }

    if (wd_network_udp_->open()) {
        // Relay first, so the workers never see proxied datagrams without a
        // receiver.
        udp_relay_ = std::make_unique<UdpRelay>(
            ioc_, udp_session_table_, socks5_udp_mgr_, wd_network_udp_->handle());
        if (udp_relay_->start()) {
            wd_network_udp_->set_sink(udp_relay_.get());
            PC_LOG_INFO("UDP Relay started");
        }
        wd_network_udp_->start(2);
        PC_LOG_INFO("WinDivert UDP NETWORK layer started");
    }
}

int app::run_main_loop() {
    if (gui_) {
        gui_->run();
        return 0;
    }

    if (GetConsoleWindow() != nullptr) {
        // Console session (console build, or a debug build's console): keep
        // the proxy running until the user stops it. Previously this slept
        // one hour and then shut the proxy down.
        g_console_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_console_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_console_stop && SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
            PC_LOG_WARN("Running without a window. Press Ctrl+C or close this console to exit.");
            WaitForSingleObject(g_console_stop, INFINITE);
            PC_LOG_INFO("Console stop requested");
            return 0;
        }
        PC_LOG_ERROR("SetConsoleCtrlHandler failed ({}); falling back to a message box",
                     GetLastError());
    }

    // GUI-subsystem build without a usable WebView2 window and without a
    // console: the only visible surface is a message box. The proxy keeps
    // running until the user dismisses it.
    PC_LOG_ERROR("No window could be created; showing the browser fallback dialog");
    const std::string url =
        std::format("http://127.0.0.1:{}{}", API_PORT, api_server_.bootstrap_path());
    const std::wstring text =
        L"ProxyClaw 无法创建窗口（WebView2 运行时不可用或初始化失败）。\n"
        L"代理仍在运行。可在浏览器中打开以下地址使用界面：\n\n" +
        utf8_to_wide(url) +
        L"\n\n关闭此对话框将退出 ProxyClaw。\n\n"
        L"ProxyClaw could not create its window (WebView2 Runtime missing or failed to start).\n"
        L"The proxy is still running; open the address above in a browser to use the UI.\n"
        L"Closing this dialog exits ProxyClaw.";
    MessageBoxW(nullptr, text.c_str(), L"ProxyClaw",
                MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
    return 0;
}

void app::shutdown() noexcept {
    if (shut_down_.exchange(true)) return;
    PC_LOG_INFO("Shutting down...");

    // A window move/resize may still be waiting in the debouncer.
    geometry_saver_.flush();

    // DNS first — touches system-wide state visible to the user.
    dns_mgr_.stop();

    // WinDivert teardown follows the documented order: WinDivertShutdown ->
    // join every thread that uses the handle -> WinDivertClose. Phase 1 stops
    // receiving and joins the dedicated threads; the handles are closed only
    // after the io_context workers (strand handlers, UDP relay injection,
    // IOCP receive completions) are joined below.
    socks5_udp_mgr_.stop();
    if (wd_network_udp_) wd_network_udp_->set_sink(nullptr);
    if (udp_relay_)      udp_relay_->stop();
    if (wd_network_udp_) wd_network_udp_->stop_workers();
    if (wd_socket_udp_)  wd_socket_udp_->stop();

    if (wd_socket_)  wd_socket_->stop();
    if (wd_network_) wd_network_->stop_workers();
    if (wd_network_v6_) wd_network_v6_->stop_workers();
    // Drain parked SYNs (sent through the still-open NETWORK handle) now that
    // no worker can park new ones.
    if (parker_)     parker_->stop();
    PC_LOG_INFO("WinDivert layers stopped");

    acceptor_.stop();
    acceptor_v6_.stop();
    api_server_.stop();

    ioc_.stop();
    for (auto& w : workers_) w.join();
    PC_LOG_INFO("io_context stopped, {} workers joined", num_workers_);

    // Nothing can touch a WinDivert handle any more.
    if (wd_network_udp_) wd_network_udp_->close();
    if (wd_socket_udp_)  wd_socket_udp_->close();
    if (wd_socket_)      wd_socket_->close();
    if (wd_network_)     wd_network_->close();
    if (wd_network_v6_)  wd_network_v6_->close();
    PC_LOG_INFO("WinDivert layers closed");

    tree_mgr_.stop();

    icons_.shutdown();
    if (autostart_check_.joinable()) autostart_check_.join();
    PC_LOG_INFO("Goodbye!");
    quill::Backend::stop();
    if (g_console_done) SetEvent(g_console_done);
}

} // namespace clew
