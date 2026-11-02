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
#include "core/log.hpp"
#include "transport/middleware.hpp"
#include "transport/route_registry.hpp"

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

http_api_server::http_api_server(int port, api_context& ctx, std::string static_dir)
    : port_(port)
    , static_dir_(std::move(static_dir))
    , ctx_(ctx)
    , auth_(port, token_from_env_or(generate_session_token())) {
    if (const char* dev = std::getenv("PROXYCLAW_DEV_URL"); dev && *dev) {
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

    server_thread_ = std::jthread([this]() {
        PC_LOG_INFO("[api] HTTP API server listening on 127.0.0.1:{}", port_);
        if (!server_.listen("127.0.0.1", port_)) {
            PC_LOG_ERROR("[api] failed to bind port {}", port_);
            running_ = false;
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return running_;
}

void http_api_server::stop() {
    if (!running_.exchange(false)) return;
    server_.stop();
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    PC_LOG_INFO("[api] HTTP API server stopped");
}

std::string http_api_server::get_executable_dir() {
    char path[MAX_PATH];
    if (DWORD len = GetModuleFileNameA(nullptr, path, MAX_PATH); len > 0 && len < MAX_PATH) {
        std::string_view sv{path, static_cast<std::size_t>(len)};
        if (auto last_sep = sv.find_last_of("\\/"); last_sep != std::string_view::npos) {
            return std::string(sv.substr(0, last_sep));
        }
    }
    return ".";
}

void http_api_server::setup_static_files() {
    // All candidates are anchored to either an explicit --static-dir or
    // the exe directory. We deliberately do NOT include cwd-relative
    // paths ("./frontend/dist" etc.) anymore — Task Scheduler launches
    // proxyclaw.exe with cwd=system32 and Explorer double-click uses the
    // desktop folder, neither of which is reachable from clew's resources.
    // The two exe_dir candidates cover release zip layout
    // (exe_dir/frontend/dist) and dev build layout
    // (build/Release/proxyclaw.exe → exe_dir/../../frontend/dist).
    const std::vector<std::string> candidates = {
        static_dir_,
        get_executable_dir() + "/frontend/dist",
        get_executable_dir() + "/../../frontend/dist",
    };

    for (const auto& path : candidates) {
        if (path.empty()) continue;
        std::string index_path = path + "/index.html";
        if (GetFileAttributesA(index_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (server_.set_mount_point("/", path)) {
                PC_LOG_INFO("[api] serving static files from {}", path);
                return;
            }
        }
    }
    PC_LOG_WARN("[api] static files directory not found; web UI unavailable");
}

} // namespace clew::transport
