#include "services/diagnostics_service.hpp"

#include <ctime>
#include <exception>
#include <format>
#include <string>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "common/api_exception.hpp"
#include "config/config_store.hpp"
#include "core/diagnostics.hpp"
#include "core/log_tail.hpp"

namespace clew {

namespace {

std::string query_os_info() {
    using rtl_get_version_t = LONG(WINAPI*)(OSVERSIONINFOEXW*);
    OSVERSIONINFOEXW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (auto* ntdll = GetModuleHandleA("ntdll.dll")) {
        auto fn = reinterpret_cast<rtl_get_version_t>(GetProcAddress(ntdll, "RtlGetVersion"));
        if (fn && fn(&vi) == 0) {
            return std::format("Windows {}.{}.{} (x64)",
                               vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        }
    }
    return "Windows (x64)";
}

} // namespace

diagnostics_service::diagnostics_service(config_store& cfg,
                                         std::function<nlohmann::json()> stats_fn,
                                         std::function<nlohmann::json()> env_fn,
                                         std::filesystem::path log_path,
                                         std::string version)
    : cfg_(cfg)
    , stats_fn_(std::move(stats_fn))
    , env_fn_(std::move(env_fn))
    , log_path_(std::move(log_path))
    , version_(std::move(version)) {}

diagnostics_export_result diagnostics_service::export_bundle() const {
    diagnostics_bundle_input in;
    in.version       = version_;
    in.timestamp_utc = std::time(nullptr);
    in.os_info       = query_os_info();

    try {
        const std::string raw = cfg_.raw_json();
        auto parsed = nlohmann::json::parse(raw, nullptr, /*allow_exceptions=*/false);
        in.raw_config = parsed.is_discarded()
            ? nlohmann::json{{"error", "failed to parse raw config JSON"}}
            : std::move(parsed);
    } catch (const std::exception& e) {
        in.raw_config = nlohmann::json{{"error", e.what()}};
    }

    if (stats_fn_) {
        try {
            in.stats = stats_fn_();
        } catch (const std::exception& e) {
            in.stats = nlohmann::json{{"error", e.what()}};
        }
    } else {
        in.stats = nlohmann::json::object();
    }

    if (env_fn_) {
        try {
            in.env = env_fn_();
        } catch (const std::exception& e) {
            in.env = nlohmann::json{{"error", e.what()}};
        }
    } else {
        in.env = nlohmann::json::object();
    }

    try {
        // Cap log export at 2 MiB / 20,000 recent lines so bundle size stays predictable.
        auto tail = read_log_tail(log_path_, 2u * 1024u * 1024u, 20000u);
        in.log_exists    = tail.exists;
        in.log_truncated = tail.truncated;
        in.log_text      = std::move(tail.text);
    } catch (const std::exception& e) {
        in.log_exists    = false;
        in.log_truncated = false;
        in.log_text      = std::format("# Failed to read proxyclaw.log: {}\n", e.what());
    }

    try {
        diagnostics_export_result out;
        out.filename  = format_diagnostics_filename(in.timestamp_utc);
        out.zip_bytes = build_diagnostics_zip(in);
        return out;
    } catch (const std::exception& e) {
        throw api_exception{api_error::io_error, std::format("生成诊断包失败: {}", e.what())};
    }
}

} // namespace clew
