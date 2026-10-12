#include "services/shell_service.hpp"

#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>

#include "common/api_exception.hpp"
#include "core/exe_paths.hpp"
#include "core/log_tail.hpp"

namespace clew {

nlohmann::json shell_service::browse_exe() {
    wchar_t file_path[32768] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = nullptr;
    ofn.lpstrTitle  = L"选择需要代理的程序";
    ofn.lpstrFilter = L"可执行程序 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrFile   = file_path;
    ofn.nMaxFile    = static_cast<DWORD>(sizeof(file_path) / sizeof(file_path[0]));
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!GetOpenFileNameW(&ofn)) {
        nlohmann::json j;
        j["cancelled"] = true;
        return j;
    }

    // The JSON API carries UTF-8; the Windows dialog returns UTF-16.
    const int needed = WideCharToMultiByte(CP_UTF8, 0, file_path, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        throw api_exception{api_error::invalid_argument, "invalid executable path"};
    }
    std::string full(static_cast<std::size_t>(needed), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, file_path, -1, full.data(), needed, nullptr, nullptr)) {
        throw api_exception{api_error::invalid_argument, "failed to encode executable path"};
    }
    full.pop_back(); // Omit the terminating NUL from JSON strings.
    std::string dir;
    std::string name;
    if (auto last_sep = full.find_last_of("\\/"); last_sep != std::string::npos) {
        dir  = full.substr(0, last_sep + 1);
        name = full.substr(last_sep + 1);
    } else {
        name = full;
    }

    nlohmann::json j;
    j["path"] = full;
    j["dir"]  = dir;
    j["name"] = name;
    return j;
}

nlohmann::json shell_service::read_log() {
    try {
        auto path = exe_relative("proxyclaw.log");
        auto tail = read_log_tail(path);
        auto utf8 = path.u8string();
        return {{"path", std::string(utf8.begin(), utf8.end())},
                {"text", std::move(tail.text)}, {"exists", tail.exists},
                {"truncated", tail.truncated}};
    } catch (const std::exception&) {
        throw api_exception{api_error::io_error, "无法读取运行日志，请稍后重试"};
    }
}

void shell_service::reveal(std::string_view path) {
    if (path.empty()) {
        throw api_exception{api_error::invalid_argument, "path is required"};
    }

    std::string utf8{path};
    int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (needed <= 0) {
        throw api_exception{api_error::invalid_argument, "invalid UTF-8 path"};
    }
    std::wstring wpath(static_cast<std::size_t>(needed), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wpath.data(), needed)) {
        throw api_exception{api_error::invalid_argument, "invalid UTF-8 path"};
    }
    wpath.pop_back();

    std::wstring wcmd = L"/select,\"" + wpath + L"\"";
    ShellExecuteW(nullptr, L"open", L"explorer.exe", wcmd.c_str(), nullptr, SW_SHOWNORMAL);
}

} // namespace clew
