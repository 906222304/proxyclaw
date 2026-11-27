#include "transport/http_api_server.hpp"

#include <chrono>
#include <cstdlib>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "common/api_context.hpp"
#include "common/dev_hooks.hpp"
#include "core/exe_paths.hpp"
#include "core/log.hpp"
#include "transport/middleware.hpp"
#include "transport/route_registry.hpp"
#include "transport/static_files.hpp"

// Handler modules define register_* functions in the ::clew namespace.
namespace clew {
void register_autostart_handlers(route_registry&);
void register_config_handlers(route_registry&);
void register_connection_handlers(route_registry&);
void register_group_handlers(route_registry&);
void register_icon_handlers(route_registry&);
void register_process_handlers(route_registry&);
void register_rule_handlers(route_registry&);
void register_shell_handlers(route_registry&);
void register_stats_handlers(route_registry&);
} // namespace clew

namespace clew::transport {

namespace {

// 32 random bytes as 64 hex chars. Falls back to a launch-unique value only if
// the system RNG is unavailable, which would also break TLS on the machine.
std::string generate_session_token() {
    unsigned char bytes[32]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        PC_LOG_ERROR("[api] BCryptGenRandom failed; using a weak session token");
        LARGE_INTEGER qpc{};
        QueryPerformanceCounter(&qpc);
        const auto seed = static_cast<unsigned long long>(qpc.QuadPart) ^ GetCurrentProcessId();
        for (size_t i = 0; i < sizeof(bytes); ++i) {
            bytes[i] = static_cast<unsigned char>((seed >> ((i % 8) * 8)) ^ (i * 131));
        }
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(sizeof(bytes) * 2);
    for (unsigned char b : bytes) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

} // namespace

http_api_server::http_api_server(int port, api_context& ctx, std::filesystem::path static_dir)
    : port_(port)
    , static_dir_(std::move(static_dir))
    , ctx_(ctx)
    // Both env hooks are test/developer aids and are honoured only with dev
    // hooks enabled (debug build or --dev-hooks; see common/dev_hooks.hpp).
    , auth_(port, dev_hooks_enabled() ? token_from_env_or(generate_session_token())
                                      : generate_session_token()) {
    if (const char* dev = dev_env("PROXYCLAW_DEV_URL")) {
        auth_.allow_origin(dev);
    }
    // Thread pool sized for our actual load: 3 polling endpoints
    // (stats/tcp/udp) + occasional CRUD + icon fetches. Default would
    // be std::thread::hardware_concurrency(); 8 is a safe fixed cap
    // that doesn't depend on machine class. The earlier 32 was sized
    // for SSE long-lived connections, which the project no longer has.
    server_.new_task_queue = [] { return new httplib::ThreadPool(8); };

    install_auth_gate(server_, auth_);
    install_default_headers(server_);
    install_session_route(server_, auth_);

    clew::route_registry reg(server_, ctx_);
    clew::register_autostart_handlers(reg);
    clew::register_config_handlers(reg);
    clew::register_connection_handlers(reg);
    clew::register_group_handlers(reg);
    clew::register_icon_handlers(reg);
    clew::register_process_handlers(reg);
    clew::register_rule_handlers(reg);
    clew::register_shell_handlers(reg);
    clew::register_stats_handlers(reg);

    setup_static_files();
}

http_api_server::~http_api_server() {
    stop();
}

bool http_api_server::start() {
    if (running_.exchange(true)) return true;

    // Bind synchronously so a port conflict is reported here, not guessed
    // from a timer: once bind_to_port() returns true the socket is bound and
    // listening (connections queue in the backlog until the accept loop runs).
    if (!server_.bind_to_port("127.0.0.1", port_)) {
        PC_LOG_ERROR("[api] failed to bind 127.0.0.1:{}", port_);
        running_ = false;
        return false;
    }
    PC_LOG_INFO("[api] HTTP API server listening on 127.0.0.1:{}", port_);

    accept_loop_done_ = false;
    server_thread_ = std::jthread([this]() {
        if (!server_.listen_after_bind()) {
            PC_LOG_ERROR("[api] accept loop on port {} ended with an error", port_);
        }
        accept_loop_done_ = true;
    });
    // Wait (bounded) until the accept loop is running, so an early stop()
    // cannot slip in before httplib marks itself running and then miss it.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!server_.is_running() && !accept_loop_done_ &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!server_.is_running()) {
        PC_LOG_ERROR("[api] accept loop on port {} did not start", port_);
        stop();
        return false;
    }
    return true;
}

void http_api_server::stop() {
    if (!running_.exchange(false)) return;
    server_.stop();
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    PC_LOG_INFO("[api] HTTP API server stopped");
}

void http_api_server::setup_static_files() {
    const auto exe_dir = clew::exe_directory();
    if (const auto mounted = mount_static_files(server_, static_dir_, exe_dir)) {
        PC_LOG_INFO("[api] serving static files from {}", *mounted);
        return;
    }
    PC_LOG_WARN("[api] static files directory not found (exe_dir={}); web UI unavailable",
                clew::path_to_utf8(exe_dir));
}

} // namespace clew::transport
