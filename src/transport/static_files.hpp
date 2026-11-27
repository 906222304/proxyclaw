#pragma once

// Static frontend directory discovery and UTF-8 mounting for cpp-httplib.
//
// cpp-httplib's Server::set_mount_point() / FileStat / mmap::open on Windows
// unconditionally decode the directory std::string as UTF-8
// (MultiByteToWideChar(CP_UTF8, ...)). Passing an ANSI/GBK string from
// GetModuleFileNameA silently fails to mount "/" whenever the install path
// contains non-ASCII characters (e.g. Chinese user names or Desktop folders),
// producing HTTP 404 on http://127.0.0.1:18080/.
//
// Keep candidate discovery strictly wide (std::filesystem::path) and encode
// to UTF-8 right at the cpp-httplib boundary.

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <httplib.h>

#include "core/exe_paths.hpp"

namespace clew::transport {

// Normalize a directory path for cpp-httplib base_dir concatenation
// (`entry.base_dir + "/index.html"`), stripping trailing path separators so a
// caller-supplied `--static-dir C:\foo\dist\` does not yield redundant slashes.
[[nodiscard]] inline std::filesystem::path normalize_mount_dir(const std::filesystem::path& dir) {
    auto norm = dir.lexically_normal();
    std::wstring s = norm.wstring();
    while (s.size() > 1 && (s.back() == L'\\' || s.back() == L'/')) {
        if (s.size() == 3 && s[1] == L':') break;  // preserve drive root "C:\"
        s.pop_back();
    }
    return std::filesystem::path{std::move(s)};
}

// All candidates are anchored to either an explicit --static-dir or the exe
// directory. Cwd-relative paths ("./frontend/dist" etc.) are deliberately
// excluded — Task Scheduler runs with cwd=system32 and Explorer double-click
// uses the desktop folder.
// Covers release zip layout (exe_dir/frontend/dist) and dev build layout
// (build/Release/proxyclaw.exe -> exe_dir/../../frontend/dist).
[[nodiscard]] inline std::optional<std::filesystem::path> find_static_dir(
    const std::filesystem::path& explicit_dir,
    const std::filesystem::path& exe_dir) {
    std::vector<std::filesystem::path> candidates;
    candidates.reserve(3);
    if (!explicit_dir.empty()) candidates.push_back(explicit_dir);
    if (!exe_dir.empty()) {
        candidates.push_back(exe_dir / L"frontend" / L"dist");
        candidates.push_back(exe_dir / L".." / L".." / L"frontend" / L"dist");
    }

    for (const auto& candidate : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(candidate / L"index.html", ec) && !ec) {
            return normalize_mount_dir(candidate);
        }
    }
    return std::nullopt;
}

// Locate and mount the static frontend directory at "/".
// Returns the UTF-8 path mounted on success, or std::nullopt if no candidate
// had index.html or cpp-httplib rejected the directory.
[[nodiscard]] inline std::optional<std::string> mount_static_files(
    httplib::Server& server,
    const std::filesystem::path& explicit_dir,
    const std::filesystem::path& exe_dir) {
    const auto dir = find_static_dir(explicit_dir, exe_dir);
    if (!dir) return std::nullopt;

    const std::string utf8_dir = clew::path_to_utf8(*dir);
    if (utf8_dir.empty()) return std::nullopt;
    if (!server.set_mount_point("/", utf8_dir)) return std::nullopt;
    return utf8_dir;
}

} // namespace clew::transport
