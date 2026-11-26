#pragma once

// interception.mode = "hook": per-process interception without the WinDivert
// driver. proxyclaw_hook64.dll is loaded into proxied processes and rewrites
// their TCP connects in user mode:
//
//   app connect(dst) --hook--> pipe: "pid P, port S -> dst?"   (this class)
//        <- proxy, relay port R (flow S -> dst published first)
//   app connect(127.0.0.1:R) --> hook::acceptor --> SOCKS5 CONNECT dst
//
// Decisions use the same process tree and rules as the WinDivert path, on
// the same strand. Getting the DLL in:
//   - running proxied processes: a 1 s sweep of the tree injects any that
//     do not have it yet (their connections before that went direct);
//   - children of an injected process: the DLL asks (msg_type::child) and
//     adds itself to the suspended child's imports before it runs, so the
//     child's first connection is already covered.
//
// Not covered in this mode: UDP (goes direct), 32-bit processes, sandboxed
// (AppContainer / low integrity) processes and those that only load
// Microsoft-signed images, and programs that make raw syscalls instead of
// going through ws2_32.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define ASIO_STANDALONE
#include <asio.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/decision_log.hpp"
#include "domain/process_tree_manager.hpp"
#include "hook/hook_acceptor.hpp"
#include "hook/hook_flow_table.hpp"
#include "hook/hook_inject_tracker.hpp"
#include "hook/hook_injector.hpp"
#include "hook/hook_pipe_server.hpp"
#include "hook/hook_protocol.hpp"
#include "proxy/ipv6_egress.hpp"
#include "proxy/proxy_group_table.hpp"

namespace clew::hook {

class mode {
public:
    using strand_type = asio::strand<asio::io_context::executor_type>;

    mode(asio::io_context& ioc, strand_type& strand, domain::process_tree_manager& tree_mgr,
         const proxy_group_table& groups, ipv6_egress& egress, DecisionLog* decisions,
         const std::atomic<bool>& ipv6_block, const std::atomic<bool>& ipv6_proxy);
    ~mode();

    mode(const mode&) = delete;
    mode& operator=(const mode&) = delete;

    // False when the 64-bit DLL is missing or the control pipe cannot be
    // created; nothing is intercepted then. `dll32` is optional (missing
    // proxyclaw_hook32.dll degrades gracefully to skipping 32-bit processes).
    bool start(const std::filesystem::path& dll64,
               const std::filesystem::path& dll32 = {});
    void stop();

    uint16_t relay_port_v4() const noexcept { return port_v4_.load(std::memory_order_relaxed); }
    uint16_t relay_port_v6() const noexcept { return port_v6_.load(std::memory_order_relaxed); }

    // Thread-safe snapshot of tracked (pid, psn) -> inject_status for process
    // tree and connection views.
    status_map status_snapshot() const;

    // Optional callback posted on the strand whenever injection outcomes change
    // so process_projection pushes fresh hook_status badges promptly.
    void set_on_status_changed(std::function<void()> cb) {
        on_status_changed_ = std::move(cb);
    }

    nlohmann::json stats() const;

private:
    using key = inject_tracker::key;   // (pid, psn)

    reply on_request(const request& req, DWORD client_pid);   // pipe threads
    reply decide_connect(const request& req, DWORD pid);      // strand
    reply decide_child(DWORD parent, DWORD child);            // strand
    reply on_child_failed(DWORD parent, DWORD child);         // strand
    void  record(const request& req, DWORD pid, DecisionRecord& rec);
    void  notify_status_changed();

    void schedule_sweep();                                    // strand
    void publish_wanted_now();                                // strand
    void injector_loop(std::stop_token st);

    asio::io_context& ioc_;
    strand_type& strand_;
    domain::process_tree_manager& tree_mgr_;
    const proxy_group_table& groups_;
    ipv6_egress& egress_;
    DecisionLog* decisions_;
    const std::atomic<bool>& ipv6_block_;
    const std::atomic<bool>& ipv6_proxy_;
    const DWORD self_pid_;

    std::wstring dll_path_;
    std::wstring dll32_path_;
    flow_table flows_;
    acceptor acceptor_v4_;
    acceptor acceptor_v6_;
    std::atomic<uint16_t> port_v4_{0};
    std::atomic<uint16_t> port_v6_{0};
    std::unique_ptr<pipe_server> pipe_;
    asio::steady_timer sweep_timer_;
    std::atomic<bool> running_{false};
    std::function<void()> on_status_changed_;

    // Injector thread: the strand hands it the live proxied set each sweep.
    mutable std::mutex inj_mu_;
    std::condition_variable_any inj_cv_;
    inject_tracker tracker_;
    std::jthread injector_;

    std::atomic<uint64_t> n_proxy_{0}, n_direct_{0}, n_block_{0}, n_child_inject_{0},
                          n_child_skip_{0}, n_timeout_{0}, n_inject_ok_{0}, n_inject_skip_{0},
                          n_inject_fail_{0};
};

} // namespace clew::hook
