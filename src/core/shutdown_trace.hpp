#pragma once

// Synchronous shutdown breadcrumbs in proxyclaw.shutdown.log next to the exe.
// Written straight to the file with WriteFile, so they survive a crash or a
// hang in the logging backend (the quill flush itself was seen to hang on CI).

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <string_view>

#include "core/exe_paths.hpp"

namespace clew {

class shutdown_trace {
public:
    shutdown_trace() {
        handle_ = CreateFileW(exe_relative(L"proxyclaw.shutdown.log").c_str(), FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        mark("begin");
    }
    ~shutdown_trace() {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }
    shutdown_trace(const shutdown_trace&) = delete;
    shutdown_trace& operator=(const shutdown_trace&) = delete;

    void mark(std::string_view what) noexcept {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start_).count();
        char line[160];
        const int n = std::snprintf(line, sizeof(line), "pid=%lu +%lldms %.*s\r\n",
                                    GetCurrentProcessId(), static_cast<long long>(ms),
                                    static_cast<int>(what.size()), what.data());
        if (n <= 0) return;
        DWORD written = 0;
        WriteFile(handle_, line, static_cast<DWORD>(n < static_cast<int>(sizeof(line)) ? n : sizeof(line) - 1),
                  &written, nullptr);
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
};

} // namespace clew
