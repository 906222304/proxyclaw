#pragma once

// All clew resources (proxyclaw.log, proxyclaw.json, dns_state.json, frontend/dist)
// must resolve against the directory containing proxyclaw.exe — not the process
// cwd, which is unpredictable (Task Scheduler launches with cwd=system32,
// Explorer double-click uses the desktop folder, shell uses whatever the
// user happens to be in). These helpers wrap GetModuleFileNameW once so
// every consumer goes through the same code path.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlobj.h>

#include <filesystem>
#include <string>
#include <string_view>

#include "scoped_exit.hpp"

namespace clew {

// Absolute path of the running proxyclaw.exe. Grows past MAX_PATH so long
// install paths never silently truncate. Falls back to an empty path only if
// GetModuleFileNameW itself fails.
[[nodiscard]] inline std::filesystem::path exe_path() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD cap = static_cast<DWORD>(buf.size());
        const DWORD len = GetModuleFileNameW(nullptr, buf.data(), cap);
        if (len == 0) return {};
        if (len < cap) {
            buf.resize(len);
            return std::filesystem::path{std::move(buf)};
        }
        if (buf.size() >= 32768) return {};
        buf.resize(buf.size() * 2);
    }
}

// Convert a filesystem path to UTF-8 unconditionally (independent of the
// process ANSI code page; never throws on non-ASCII characters). Required when
// passing paths to APIs that always interpret std::string as UTF-8, such as
// cpp-httplib's set_mount_point() or UTF-8 log sinks.
[[nodiscard]] inline std::string path_to_utf8(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

// Directory portion of the running proxyclaw.exe path. Falls back to "." if
// exe_path() failed.
[[nodiscard]] inline std::filesystem::path exe_directory() {
    auto p = exe_path();
    return p.empty() ? std::filesystem::path{L"."} : p.parent_path();
}

// Resolve a sibling resource of proxyclaw.exe by name. e.g. exe_relative("proxyclaw.log")
// → "C:\Users\foo\Downloads\clew\proxyclaw.log".
[[nodiscard]] inline std::filesystem::path exe_relative(std::wstring_view name) {
    return exe_directory() / name;
}

[[nodiscard]] inline std::filesystem::path exe_relative(std::string_view name) {
    return exe_directory() / name;
}

// %LOCALAPPDATA% via the known-folder API (correct for non-ASCII user names,
// independent of the environment block). Empty path on failure — callers are
// expected to fall back to an exe-relative location.
[[nodiscard]] inline std::filesystem::path local_app_data_directory() {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &raw)))
        return {};
    scoped_exit free_raw{[&] { CoTaskMemFree(raw); }};
    return std::filesystem::path{raw};
}

} // namespace clew
