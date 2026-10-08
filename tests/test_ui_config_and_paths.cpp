// Windows-only regression checks. Dialog/Explorer calls are faked; the real
// UTF-8/UTF-16 conversion and configuration serialization are exercised.
// Example (Zig; nlohmann/json.hpp must exist under build/test-deps):
// zig c++ -std=c++23 -Isrc -Ibuild/test-deps tests/test_ui_config_and_paths.cpp
//     src/common/api_exception.cpp -lshell32 -lws2_32 -o build/test_ui_config_and_paths.exe
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include "config/types.hpp"

static std::wstring chosen_path;
static std::wstring revealed_path;
static bool cancel_dialog = false;
static BOOL fake_open_file(OPENFILENAMEW* ofn) {
    if (std::wstring(ofn->lpstrTitle) != L"选择需要代理的程序")
        throw std::runtime_error("dialog title is not Chinese");
    if (std::wstring(ofn->lpstrFilter) != L"可执行程序 (*.exe)")
        throw std::runtime_error("dialog filter is not Chinese");
    if (cancel_dialog) return FALSE;
    if (chosen_path.size() + 1 > ofn->nMaxFile) throw std::runtime_error("path buffer too small");
    std::copy(chosen_path.begin(), chosen_path.end(), ofn->lpstrFile);
    ofn->lpstrFile[chosen_path.size()] = L'\0';
    return TRUE;
}
static HINSTANCE fake_shell_execute(HWND, LPCWSTR, LPCWSTR, LPCWSTR args, LPCWSTR, INT) {
    revealed_path = args;
    return reinterpret_cast<HINSTANCE>(33);
}
#define GetOpenFileNameW fake_open_file
#define ShellExecuteW fake_shell_execute
#include "../src/services/shell_service.cpp"
#undef GetOpenFileNameW
#undef ShellExecuteW

static void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
    std::cout << "PASS " << message << '\n';
}
int main() {
    try {
        check(clew::UiConfig{}.close_to_tray, "new configuration keeps running in background");
        check(nlohmann::json::object().get<clew::UiConfig>().close_to_tray,
              "missing setting defaults to background mode");
        check(!nlohmann::json{{"close_to_tray", false}}.get<clew::UiConfig>().close_to_tray,
              "explicit exit preference is preserved");
        chosen_path = L"C:\\应用程序\\中文示例.exe";
        auto result = clew::shell_service::browse_exe();
        check(result["path"] == "C:\\应用程序\\中文示例.exe", "Chinese full path is UTF-8");
        check(result["dir"] == "C:\\应用程序\\" && result["name"] == "中文示例.exe",
              "Chinese directory and filename are preserved");
        chosen_path = L"C:\\应用程序\\\U0001F680.exe";
        result = clew::shell_service::browse_exe();
        check(result["name"] == "\U0001F680.exe", "supplementary Unicode characters are preserved");
        cancel_dialog = true;
        check(clew::shell_service::browse_exe()["cancelled"] == true, "cancel remains supported");
        clew::shell_service::reveal("C:\\应用程序\\中文示例.exe");
        check(revealed_path == L"/select,\"C:\\应用程序\\中文示例.exe\"", "Explorer receives UTF-16 path");
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
