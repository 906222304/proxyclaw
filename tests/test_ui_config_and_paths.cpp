// Windows-only regression checks. Dialog/Explorer calls are faked; the real
// UTF-8/UTF-16 conversion and configuration serialization are exercised.
// Example (Zig; nlohmann/json.hpp must exist under build/test-deps):
// zig c++ -std=c++23 -Isrc -Ibuild/test-deps tests/test_ui_config_and_paths.cpp
//     src/common/api_exception.cpp -lshell32 -lws2_32 -o build/test_ui_config_and_paths.exe
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include "config/types.hpp"
#include "transport/static_files.hpp"

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

static void test_unicode_static_mount() {
    namespace fs = std::filesystem;
    const fs::path unicode_dir = fs::path(L"C:\\用户\\张三\\桌面\\代理工具\\frontend\\dist");
    check(clew::path_to_utf8(unicode_dir) == "C:\\用户\\张三\\桌面\\代理工具\\frontend\\dist",
          "path_to_utf8 preserves Chinese directory path");

    const auto stamp = std::to_wstring(GetCurrentProcessId()) + L"_" +
                       std::to_wstring(GetTickCount64());
    const fs::path base = fs::temp_directory_path() / (L"proxyclaw_中文测试_" + stamp);
    const fs::path dist = base / L"frontend" / L"dist";
    const fs::path override_dir = base / L"自定义前端目录";
    struct cleanup_guard {
        fs::path root;
        ~cleanup_guard() {
            std::error_code ec;
            fs::remove_all(root, ec);
        }
    } guard{base};

    fs::create_directories(dist);
    fs::create_directories(override_dir);
    const std::string html = "<!doctype html><div id=\"root\">ProxyClaw中文</div>";
    {
        std::ofstream out(dist / L"index.html", std::ios::binary);
        out << html;
    }
    {
        std::ofstream out(override_dir / L"index.html", std::ios::binary);
        out << "override-ok";
    }

    httplib::Server server;
    const auto mounted = clew::transport::mount_static_files(server, {}, base);
    check(mounted.has_value(), "mount_static_files succeeds for Chinese exe directory");
    check(mounted->find("proxyclaw_中文测试_") != std::string::npos,
          "mounted path is reported in UTF-8");

    const int port = server.bind_to_any_port("127.0.0.1");
    check(port > 0, "ephemeral httplib bind succeeds");
    std::jthread th([&] { server.listen_after_bind(); });
    for (int i = 0; i < 200 && !server.is_running(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    httplib::Client cli("127.0.0.1", port);
    auto res = cli.Get("/");
    server.stop();
    if (th.joinable()) th.join();

    check(res && res->status == 200, "GET / from Chinese install directory returns HTTP 200 (not 404)");
    check(res && res->body == html, "GET / returns exact index.html body");

    httplib::Server server2;
    const fs::path trailing = fs::path(override_dir.wstring() + L"\\");
    const auto mounted2 = clew::transport::mount_static_files(server2, trailing, base);
    check(mounted2.has_value() && mounted2->find("自定义前端目录") != std::string::npos,
          "explicit --static-dir with Chinese path and trailing slash mounts cleanly");
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
        test_unicode_static_mount();
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
