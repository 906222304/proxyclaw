#pragma once

// Developer / test hooks that are read from the environment.
//
// The process runs elevated, while HKCU environment variables can be set by
// any unelevated process of the same user. A release build must therefore not
// let the environment redirect the UI (PROXYCLAW_DEV_URL), pre-choose the API
// session token (PROXYCLAW_API_TOKEN) or reconfigure the embedded browser
// (WEBVIEW2_* overrides such as --remote-debugging-port or a different browser
// executable folder).
//
// The hooks are honoured only when
//   - the binary is a debug build (NDEBUG not defined), or
//   - the elevated command line carries --dev-hooks (an unelevated process
//     cannot add arguments to a UAC launch or to the autostart task without
//     going through the elevation boundary).
// main() calls strip_untrusted_environment() early, so the WebView2 loader,
// which reads its overrides from the process environment, never sees them
// either.

#include <array>
#include <atomic>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace clew {

namespace detail {
inline std::atomic<bool>& dev_hooks_flag() noexcept {
    static std::atomic<bool> flag{false};
    return flag;
}
} // namespace detail

inline void enable_dev_hooks() noexcept {
    detail::dev_hooks_flag().store(true, std::memory_order_release);
}

[[nodiscard]] inline bool dev_hooks_enabled() noexcept {
#ifndef NDEBUG
    return true;
#else
    return detail::dev_hooks_flag().load(std::memory_order_acquire);
#endif
}

// Value of a developer/test environment hook, or nullptr when hooks are off
// or the variable is unset/empty.
[[nodiscard]] inline const char* dev_env(const char* name) noexcept {
    if (!dev_hooks_enabled()) return nullptr;
    const char* v = std::getenv(name);
    return (v && *v) ? v : nullptr;
}

// Environment variables that change security-relevant behaviour of the
// elevated process or of the embedded WebView2.
inline constexpr std::array<std::string_view, 10> untrusted_env_names{
    "PROXYCLAW_DEV_URL",
    "PROXYCLAW_API_TOKEN",
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_CHANNEL_SEARCH_KIND",
    "WEBVIEW2_RELEASE_CHANNELS",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
};

// Removes the variables above from this process's environment (both the CRT
// copy and the Win32 block) unless dev hooks are enabled. Returns the names
// that were present and removed, for logging.
inline std::vector<std::string> strip_untrusted_environment() {
    std::vector<std::string> removed;
    if (dev_hooks_enabled()) return removed;
    for (const auto name_sv : untrusted_env_names) {
        const std::string name{name_sv};
        const bool crt_set = std::getenv(name.c_str()) != nullptr;
        const bool os_set  = GetEnvironmentVariableA(name.c_str(), nullptr, 0) != 0;
        if (!crt_set && !os_set) continue;
        _putenv_s(name.c_str(), "");               // empty value deletes the CRT entry
        SetEnvironmentVariableA(name.c_str(), nullptr);
        removed.push_back(name);
    }
    return removed;
}

} // namespace clew
