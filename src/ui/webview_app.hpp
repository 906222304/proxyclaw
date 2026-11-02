#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <windowsx.h>   // GET_X_LPARAM, GET_Y_LPARAM
#include <dwmapi.h>
#include <shellapi.h>
#include <wrl.h>
#ifdef PROXYCLAW_HAS_WEBVIEW2
#include <WebView2.h>
#include <WebView2EnvironmentOptions.h>
#endif
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cwctype>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include "core/exe_paths.hpp"
#include "core/log.hpp"
#include "transport/frontend_push_sink.hpp"

#pragma comment(lib, "dwmapi.lib")

namespace clew {

constexpr UINT WM_TRAYICON         = WM_APP + 1;
constexpr UINT WM_PUSH_TO_FRONTEND = WM_APP + 2;
constexpr UINT IDM_TRAY_SHOW = 40001;
constexpr UINT IDM_TRAY_EXIT = 40002;

class webview_app : public frontend_push_sink {
    // Heap-allocated payload smuggled through PostMessageW. Producer thread
    // releases ownership into LPARAM; UI thread takes it back via unique_ptr
    // in the WM_PUSH_TO_FRONTEND case.
    struct push_payload {
        std::string event;
        std::string json_body;
    };
private:

    HWND hwnd_ = nullptr;
    HICON large_icon_ = nullptr;
    HICON small_icon_ = nullptr;
    UINT dpi_ = USER_DEFAULT_SCREEN_DPI;
    std::wstring url_;
    int width_ = 1200;
    int height_ = 800;
    int init_x_ = -1;  // -1 = center
    int init_y_ = -1;
    std::wstring title_ = L"ProxyClaw";
    std::function<void()> on_close_;
    std::function<void(int, int, int, int)> on_move_resize_;
    bool initialized_ = false;
    // Controller lifecycle, distinct from `initialized_` (= "navigated"). Drives
    // ensure_webview_initialized()'s idempotent (re)try. UI-thread only: every
    // WebView2 completion handler posts back to this thread's message loop.
    enum class wv_state { not_started, in_progress, ready, failed };
    wv_state wv_state_ = wv_state::not_started;
    std::atomic<bool> close_to_tray_{true};
    bool devtools_enabled_ = true;
    bool start_minimized_ = false;  // launch directly into tray (autostart use case)
    NOTIFYICONDATAW nid_ = {};
    bool tray_created_ = false;
    // Autostart-timing resilience for the tray icon: at very early logon the
    // shell may silently reject NIM_ADD. We retry up to N times via a 500ms
    // WM_TIMER and also subscribe to the "TaskbarCreated" broadcast (sent
    // when the shell becomes ready and on Explorer crash recovery).
    UINT taskbar_created_msg_ = 0;
    int  tray_retry_count_    = 0;
    static constexpr UINT_PTR TRAY_RETRY_TIMER_ID = 1;
    static constexpr int      TRAY_MAX_RETRIES    = 10;
    // WebView2 init failure handling: one deferred retry from environment
    // creation (per Microsoft guidance), then a single visible MessageBox.
    static constexpr UINT_PTR WV_RETRY_TIMER_ID = 2;
    int  wv_retry_count_      = 0;
    bool wv_failure_notified_ = false;
    bool currently_visible_ = true;
    std::function<void()> on_ready_;
    // Fired whenever the host transitions WebView2 IsVisible. Wired in
    // app.cpp to process_projection::set_frontend_visible so the backend
    // push pipeline can drop work while the frontend is hidden.
    std::function<void(bool)> on_visibility_change_;

#ifdef PROXYCLAW_HAS_WEBVIEW2
    Microsoft::WRL::ComPtr<ICoreWebView2Controller> webview_controller_;
    Microsoft::WRL::ComPtr<ICoreWebView2> webview_;

    void initialize_webview() {
        // User data folder must NOT live next to the exe: under Program Files
        // the WebView2 sandboxed child processes cannot use it and controller
        // creation fails with 0x800700aa (issue #5; reproduced + verified
        // 2026-08-31). %LOCALAPPDATA% is Microsoft's recommended location.
        std::wstring user_data_folder;
        if (auto lad = local_app_data_directory(); !lad.empty()) {
            user_data_folder = (lad / L"ProxyClaw" / L"webview_data").wstring();
        } else {
            // Pre-fix behavior as the fallback: exe-relative. Fine everywhere
            // except Program Files, and %LOCALAPPDATA% resolution essentially
            // never fails for an interactive user.
            user_data_folder = exe_relative(L"proxyclaw_webview_data").wstring();
        }
        {
            int len = WideCharToMultiByte(CP_UTF8, 0, user_data_folder.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string udf_utf8(len - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, user_data_folder.c_str(), -1, udf_utf8.data(), len, nullptr, nullptr);
            PC_LOG_INFO("WebView2 user data folder: {}", udf_utf8);
        }

        auto options = Microsoft::WRL::Make<CoreWebView2EnvironmentOptions>();
        // WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS env var is normally honored
        // by WebView2, but only when the host did NOT call
        // put_AdditionalBrowserArguments. Since we always pass --no-proxy-server,
        // we'd otherwise mask the env var. Merge it explicitly so testers can
        // do e.g. WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222
        // to attach Playwright over CDP.
        std::wstring browser_args = L"--no-proxy-server";
        if (auto* env = std::getenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"); env && *env) {
            const int wlen = MultiByteToWideChar(CP_UTF8, 0, env, -1, nullptr, 0);
            if (wlen > 1) {
                std::wstring extra(static_cast<size_t>(wlen - 1), L'\0');
                MultiByteToWideChar(CP_UTF8, 0, env, -1, extra.data(), wlen);
                browser_args.push_back(L' ');
                browser_args.append(extra);
            }
        }
        options->put_AdditionalBrowserArguments(browser_args.c_str());

        HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
            nullptr, user_data_folder.c_str(), options.Get(),
            Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
                [this](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
                    if (FAILED(result)) {
                        on_webview_failure(result, "environment");
                        return result;
                    }
                    return env->CreateCoreWebView2Controller(
                        hwnd_,
                        Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                            [this](HRESULT result, ICoreWebView2Controller* controller) -> HRESULT {
                                if (FAILED(result) || !controller) {
                                    on_webview_failure(result, "controller");
                                    return result;
                                }
                                webview_controller_ = controller;

                                // Bounds below are physical client pixels. Let WebView2
                                // track the monitor scale itself, including across screens;
                                // changing ZoomFactor as well would scale the page twice.
                                Microsoft::WRL::ComPtr<ICoreWebView2Controller3> controller3;
                                if (SUCCEEDED(webview_controller_.As(&controller3))) {
                                    controller3->put_BoundsMode(COREWEBVIEW2_BOUNDS_MODE_USE_RAW_PIXELS);
                                    controller3->put_ShouldDetectMonitorScaleChanges(TRUE);
                                }

                                // The controller is created with IsVisible=TRUE by default. If
                                // we launched with --minimized the host window is already SW_HIDE
                                // but the WebView2 instance would otherwise keep rendering.
                                // Sync it down so process_projection's frontend_visible gate
                                // matches the real WebView2 state from the start.
                                if (!currently_visible_) {
                                    webview_controller_->put_IsVisible(FALSE);
                                }

                                // Set dark background color to prevent white flash
                                Microsoft::WRL::ComPtr<ICoreWebView2Controller2> controller2;
                                if (SUCCEEDED(webview_controller_->QueryInterface(IID_PPV_ARGS(&controller2)))) {
                                    COREWEBVIEW2_COLOR bg = {255, 9, 9, 11}; // #09090b
                                    controller2->put_DefaultBackgroundColor(bg);
                                }

                                webview_controller_->get_CoreWebView2(&webview_);
                                RECT bounds;
                                GetClientRect(hwnd_, &bounds);
                                webview_controller_->put_Bounds(bounds);

                                // Settings
                                ICoreWebView2Settings* settings = nullptr;
                                webview_->get_Settings(&settings);
                                if (settings) {
                                    settings->put_IsScriptEnabled(TRUE);
                                    settings->put_AreDefaultScriptDialogsEnabled(TRUE);
                                    settings->put_IsWebMessageEnabled(TRUE);
                                    settings->put_AreDevToolsEnabled(devtools_enabled_ ? TRUE : FALSE);
                                    // Kill the default browser context menu (Print / View source /
                                    // Save image / Reload / etc.) — meaningless in a desktop UI.
                                    // Ctrl+C/V/X still work; F12 still opens DevTools when enabled.
                                    settings->put_AreDefaultContextMenusEnabled(FALSE);

                                    // Enable non-client region support for CSS app-region: drag
                                    Microsoft::WRL::ComPtr<ICoreWebView2Settings9> settings9;
                                    if (SUCCEEDED(settings->QueryInterface(IID_PPV_ARGS(&settings9)))) {
                                        settings9->put_IsNonClientRegionSupportEnabled(TRUE);
                                        PC_LOG_INFO("WebView2 NonClientRegion support enabled");
                                    }

                                    settings->Release();
                                }

                                // Web message handler — dispatches both:
                                //   1) plain-string window-control commands
                                //      ("minimize" / "maximize" / "close")
                                //   2) structured JSON messages
                                //      ({"type":"ready", ...})
                                webview_->add_WebMessageReceived(
                                    Microsoft::WRL::Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                        [this](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                            // Only the page we navigated to may drive the host window.
                                            if (!message_source_trusted(args)) {
                                                PC_LOG_WARN("[push] ignored web message from untrusted source");
                                                return S_OK;
                                            }
                                            // Plain-string path first.
                                            LPWSTR str_msg = nullptr;
                                            if (SUCCEEDED(args->TryGetWebMessageAsString(&str_msg)) && str_msg) {
                                                std::wstring cmd(str_msg);
                                                CoTaskMemFree(str_msg);
                                                if (cmd == L"minimize") {
                                                    ShowWindow(hwnd_, SW_MINIMIZE);
                                                } else if (cmd == L"maximize") {
                                                    ShowWindow(hwnd_, IsZoomed(hwnd_) ? SW_RESTORE : SW_MAXIMIZE);
                                                } else if (cmd == L"close") {
                                                    SendMessage(hwnd_, WM_CLOSE, 0, 0);
                                                }
                                                return S_OK;
                                            }

                                            // Structured JSON path. We only care about a tiny set of
                                            // fields right now, so a substring check is sufficient
                                            // and avoids pulling nlohmann::json into this header.
                                            LPWSTR json_msg = nullptr;
                                            if (SUCCEEDED(args->get_WebMessageAsJson(&json_msg)) && json_msg) {
                                                std::wstring js(json_msg);
                                                CoTaskMemFree(json_msg);
                                                if (js.find(L"\"type\":\"ready\"") != std::wstring::npos
                                                    || js.find(L"\"type\": \"ready\"") != std::wstring::npos) {
                                                    PC_LOG_INFO("[push] frontend ready handshake received");
                                                    if (on_ready_) on_ready_();
                                                }
                                            }
                                            return S_OK;
                                        }
                                    ).Get(), nullptr);

                                webview_->Navigate(url_.c_str());
                                {
                                    // The query string carries the API session token; log only the origin/path.
                                    const std::wstring shown = url_.substr(0, url_.find(L'?'));
                                    int len = WideCharToMultiByte(CP_UTF8, 0, shown.c_str(), -1, nullptr, 0, nullptr, nullptr);
                                    std::string url_utf8(len - 1, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, shown.c_str(), -1, url_utf8.data(), len, nullptr, nullptr);
                                    PC_LOG_INFO("WebView2 initialized, navigating to {}", url_utf8);
                                }
                                initialized_ = true;
                                wv_state_ = wv_state::ready;
                                wv_retry_count_ = 0;
                                return S_OK;
                            }
                        ).Get()
                    );
                }
            ).Get()
        );

        if (FAILED(hr)) {
            on_webview_failure(hr, "environment (sync)");
        }
    }

    // Every WebView2 init failure funnels through here (env callback,
    // controller callback, synchronous env-creation HRESULT). UI thread only,
    // like all wv_state_ writers. Microsoft's guidance: retry once starting
    // from environment creation (a runtime update can invalidate the version
    // an existing environment is bound to), except on ERROR_INVALID_STATE
    // (user-data-folder/options mismatch — deterministic, retry can't help).
    // The retry is deferred through a WM_TIMER so we never re-enter
    // CreateCoreWebView2EnvironmentWithOptions from inside a completion
    // callback.
    void on_webview_failure(HRESULT hr, const char* stage) {
        PC_LOG_ERROR("WebView2 init failed at {}: {:#x}", stage, static_cast<unsigned int>(hr));
        wv_state_ = wv_state::failed;

        if (hr != HRESULT_FROM_WIN32(ERROR_INVALID_STATE) && wv_retry_count_ == 0) {
            ++wv_retry_count_;
            PC_LOG_INFO("Retrying WebView2 init once from environment creation in 1s");
            SetTimer(hwnd_, WV_RETRY_TIMER_ID, 1000, nullptr);
            return;
        }

        if (!wv_failure_notified_) {
            wv_failure_notified_ = true;
            wchar_t msg[512];
            swprintf_s(msg,
                       L"ProxyClaw 窗口初始化失败（WebView2 错误 0x%08X）。\n\n"
                       L"代理引擎仍在后台运行，可通过系统托盘菜单退出。\n\n"
                       L"详细信息见 proxyclaw.exe 所在目录的 proxyclaw.log。",
                       static_cast<unsigned int>(hr));
            MessageBoxW(hwnd_, msg, L"ProxyClaw", MB_OK | MB_ICONERROR);
        }
    }

    void resize_webview() {
        if (webview_controller_) {
            RECT bounds;
            GetClientRect(hwnd_, &bounds);
            webview_controller_->put_Bounds(bounds);
        }
    }
#else
    void initialize_webview() {
        PC_LOG_WARN("WebView2 support not compiled in (PROXYCLAW_HAS_WEBVIEW2 not defined)");
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, url_.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string url_narrow(size_needed - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, url_.c_str(), -1, url_narrow.data(), size_needed, nullptr, nullptr);
        // Console builds have no embedded host to set the session cookie, so
        // the bootstrap URL (with its token) is printed for the developer.
        PC_LOG_INFO("Please access the UI at: {}", url_narrow);
    }

    void resize_webview() {}
#endif

    void update_window_icons() {
        HINSTANCE module = GetModuleHandleW(nullptr);
        HICON large = static_cast<HICON>(LoadImageW(
            module, MAKEINTRESOURCEW(1), IMAGE_ICON,
            GetSystemMetricsForDpi(SM_CXICON, dpi_),
            GetSystemMetricsForDpi(SM_CYICON, dpi_), 0));
        HICON small_icon = static_cast<HICON>(LoadImageW(
            module, MAKEINTRESOURCEW(1), IMAGE_ICON,
            GetSystemMetricsForDpi(SM_CXSMICON, dpi_),
            GetSystemMetricsForDpi(SM_CYSMICON, dpi_), 0));
        // Keep existing icons if resource loading fails. These are owned handles;
        // LR_SHARED can cache the first requested size across later DPI changes.
        if (!large || !small_icon) {
            if (large) DestroyIcon(large);
            if (small_icon) DestroyIcon(small_icon);
            return;
        }
        SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
        SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(small_icon));
        nid_.hIcon = small_icon;
        if (tray_created_) Shell_NotifyIconW(NIM_MODIFY, &nid_);
        if (large_icon_) DestroyIcon(large_icon_);
        if (small_icon_) DestroyIcon(small_icon_);
        large_icon_ = large;
        small_icon_ = small_icon;
    }

    LRESULT on_dpi_changed(WPARAM wparam, LPARAM lparam) {
        dpi_ = HIWORD(wparam);
        const auto& rect = *reinterpret_cast<const RECT*>(lparam);
        SetWindowPos(hwnd_, nullptr, rect.left, rect.top,
                     rect.right - rect.left, rect.bottom - rect.top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        update_window_icons();
        resize_webview();
        PC_LOG_INFO("Window DPI changed: {} ({}%)", dpi_, MulDiv(dpi_, 100, 96));
        return 0;
    }

    // Idempotent, event-driven WebView2 (re)initialization chokepoint. Replaces
    // eager init at window creation so the controller is built when the shell is
    // ready (first user show, or TaskbarCreated) — avoiding the early-logon
    // 0x80070490 controller failure on elevated autostart. initialize_webview()
    // builds a fresh environment each call, satisfying MS's "recreate the
    // environment on retry" contract; on 0x80070490 no controller/webview member
    // is held, so a failed attempt leaves nothing to release.
    void ensure_webview_initialized() {
#ifdef PROXYCLAW_HAS_WEBVIEW2
        if (wv_state_ == wv_state::in_progress || wv_state_ == wv_state::ready) return;
        wv_state_ = wv_state::in_progress;   // not_started or failed -> (re)attempt
        initialize_webview();                // async; callbacks flip to ready/failed
#else
        initialize_webview();
#endif
    }

    void create_tray_icon() {
        if (tray_created_) return;
        nid_.cbSize = sizeof(NOTIFYICONDATAW);
        nid_.hWnd = hwnd_;
        nid_.uID = 1;
        nid_.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
        nid_.uCallbackMessage = WM_TRAYICON;
        // Load the embedded ProxyClaw icon (resource ID 1 from assets/proxyclaw.rc).
        // Fall back to system default if, for some reason, resource load fails.
        nid_.hIcon = small_icon_ ? small_icon_ : LoadIcon(nullptr, IDI_APPLICATION);
        wcscpy_s(nid_.szTip, L"ProxyClaw · 后台代理运行中");

        // NIM_ADD is the normal path. NIM_MODIFY catches the Win10 1903 case
        // where TaskbarCreated fires after a DPI change without the previous
        // registration being cleared (see wxWidgets#18588).
        BOOL ok = Shell_NotifyIconW(NIM_ADD, &nid_);
        if (!ok) ok = Shell_NotifyIconW(NIM_MODIFY, &nid_);

        if (!ok) {
            // Common at autostart: shell isn't ready to accept registrations
            // yet. Schedule a 500ms retry via WM_TIMER.
            if (tray_retry_count_ < TRAY_MAX_RETRIES) {
                ++tray_retry_count_;
                PC_LOG_WARN(
                    "Shell_NotifyIcon NIM_ADD/MODIFY failed (attempt {}/{}); "
                    "retrying in 500ms",
                    tray_retry_count_, TRAY_MAX_RETRIES);
                SetTimer(hwnd_, TRAY_RETRY_TIMER_ID, 500, nullptr);
            } else {
                PC_LOG_ERROR(
                    "Tray icon registration gave up after {} attempts",
                    TRAY_MAX_RETRIES);
                // A hidden app without a tray icon has no way to be reopened.
                restore_window();
            }
            return;
        }

        // NOTIFYICON_VERSION_4 enables modern callback semantics (cursor pos
        // in WM_TRAYICON's wParam, accessibility, etc.). Microsoft strongly
        // recommends this; it's not persisted across sessions so call every
        // time after a successful NIM_ADD.
        nid_.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid_);

        KillTimer(hwnd_, TRAY_RETRY_TIMER_ID);
        tray_retry_count_ = 0;
        tray_created_     = true;
    }

    void remove_tray_icon() {
        if (!tray_created_) return;
        Shell_NotifyIconW(NIM_DELETE, &nid_);
        tray_created_ = false;
    }

    void show_tray_menu() {
        POINT pt;
        GetCursorPos(&pt);
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, IDM_TRAY_SHOW, L"打开主窗口");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"退出 ProxyClaw");
        SetForegroundWindow(hwnd_);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd_, nullptr);
        DestroyMenu(menu);
    }

    void restore_window() {
        ShowWindow(hwnd_, SW_SHOW);
        ShowWindow(hwnd_, SW_RESTORE);
        SetForegroundWindow(hwnd_);
        set_visible(true);
        // Tray-only autostart deferred WebView2 init — build the controller now
        // that the user is opening the window (shell is long ready, no 0x80070490).
        // Idempotent: no-op once ready/in-progress. Called here (not inside
        // set_visible) so it's independent of set_visible's currently_visible_
        // early-return — a show always guarantees a controller.
        ensure_webview_initialized();
    }

    // Single chokepoint for visibility transitions. Drives both the
    // WebView2 controller's IsVisible (which is what makes
    // document.visibilityState reflect reality in the embedded page) and
    // the optional on_visibility_change_ callback (which lets the backend
    // push pipeline drop work while hidden). Idempotent — repeated calls
    // with the same state are no-ops, which matters for WM_SIZE bursts.
    void set_visible(bool v) {
        if (currently_visible_ == v) return;
        currently_visible_ = v;
#ifdef PROXYCLAW_HAS_WEBVIEW2
        if (webview_controller_) {
            webview_controller_->put_IsVisible(v ? TRUE : FALSE);
        }
#endif
        if (on_visibility_change_) on_visibility_change_(v);
    }

    // ---- Hit test for resize edges (title bar drag handled by WebView2 NonClientRegion) ----
    LRESULT handle_nchittest(HWND hwnd, LPARAM lparam) {
        POINT pt = { GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
        ScreenToClient(hwnd, &pt);
        RECT rc;
        GetClientRect(hwnd, &rc);

        // Don't handle resize edges when maximized
        if (IsZoomed(hwnd)) return HTCLIENT;

        int border = 6;
        UINT dpi = GetDpiForWindow(hwnd);
        if (dpi > 0) border = MulDiv(6, dpi, 96);
        bool left   = pt.x < border;
        bool right  = pt.x >= rc.right - border;
        bool top    = pt.y < border;
        bool bottom = pt.y >= rc.bottom - border;

        if (top && left)     return HTTOPLEFT;
        if (top && right)    return HTTOPRIGHT;
        if (bottom && left)  return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left)            return HTLEFT;
        if (right)           return HTRIGHT;
        if (top)             return HTTOP;
        if (bottom)          return HTBOTTOM;

        return HTCLIENT;  // WebView2 handles the rest (drag regions via CSS)
    }

    // WM_NCCALCSIZE handler — remove the system title bar and clamp the
    // proposed rect to the monitor's work area when the window is maximized
    // (otherwise it would extend over the taskbar).
    static LRESULT handle_nccalcsize(NCCALCSIZE_PARAMS* params) {
        auto& rect = params->rgrc[0];
        HMONITOR mon = MonitorFromRect(&rect, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi = { sizeof(mi) };
        if (GetMonitorInfoW(mon, &mi) &&
            rect.left <= mi.rcMonitor.left && rect.top <= mi.rcMonitor.top &&
            rect.right >= mi.rcMonitor.right && rect.bottom >= mi.rcMonitor.bottom) {
            rect = mi.rcWork;
        }
        return 0;
    }

    LRESULT on_size(WPARAM wparam) {
        resize_webview();
        if (initialized_) {
            execute_script(wparam == SIZE_MAXIMIZED
                ? L"document.documentElement.classList.add('maximized')"
                : L"document.documentElement.classList.remove('maximized')");
        }
        // Sync WebView2 IsVisible with window state. WebView2 docs (idl
        // section "IsVisible") explicitly recommend toggling on
        // SIZE_MINIMIZED / SIZE_RESTORED — without it the embedded page
        // keeps rendering and document.visibilityState stays 'visible'
        // even when the host is minimized.
        if (wparam == SIZE_MINIMIZED) {
            set_visible(false);
        } else if (wparam == SIZE_RESTORED || wparam == SIZE_MAXIMIZED) {
            set_visible(true);
        }
        return 0;
    }

    LRESULT on_close(HWND hwnd) {
        if (close_to_tray_.load(std::memory_order_relaxed)) {
            if (!tray_created_) create_tray_icon();
            if (tray_created_) {
                set_visible(false);
                ShowWindow(hwnd, SW_HIDE);
            } else {
                // Keep the proxy alive and the taskbar entry reachable while
                // Explorer is unavailable; the tray registration will retry.
                ShowWindow(hwnd, SW_MINIMIZE);
            }
            return 0;
        }
        if (on_close_) on_close_();
        DestroyWindow(hwnd);
        return 0;
    }

    LRESULT on_destroy() {
        remove_tray_icon();
        PostQuitMessage(0);
        return 0;
    }

    static LRESULT on_getminmaxinfo(HWND hwnd, LPARAM lparam) {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lparam);
        UINT dpi = GetDpiForWindow(hwnd);
        if (!dpi) dpi = GetDpiForSystem();
        mmi->ptMinTrackSize.x = MulDiv(900, dpi, 96);
        mmi->ptMinTrackSize.y = MulDiv(600, dpi, 96);
        MONITORINFO mi = { sizeof(mi) };
        if (GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi)) {
            mmi->ptMinTrackSize.x = std::min(mmi->ptMinTrackSize.x, mi.rcWork.right - mi.rcWork.left);
            mmi->ptMinTrackSize.y = std::min(mmi->ptMinTrackSize.y, mi.rcWork.bottom - mi.rcWork.top);
        }
        return 0;
    }

    LRESULT on_exitsizemove(HWND hwnd) {
        if (on_move_resize_) {
            RECT r;
            GetWindowRect(hwnd, &r);
            on_move_resize_(r.left, r.top, r.right - r.left, r.bottom - r.top);
        }
        return 0;
    }

    LRESULT on_trayicon(LPARAM lparam) {
        if (LOWORD(lparam) == WM_LBUTTONUP) {
            restore_window();
        } else if (LOWORD(lparam) == WM_RBUTTONUP) {
            show_tray_menu();
        }
        return 0;
    }

    LRESULT on_command(HWND hwnd, WPARAM wparam) {
        if (LOWORD(wparam) == IDM_TRAY_SHOW) {
            restore_window();
        } else if (LOWORD(wparam) == IDM_TRAY_EXIT) {
            if (on_close_) on_close_();
            DestroyWindow(hwnd);
        }
        return 0;
    }

    // Runs on the UI thread. Takes ownership of the heap-allocated payload
    // smuggled through the LPARAM, builds the wire-format JSON envelope
    // ({event, data}), and hands it to WebView2 for delivery to the frontend.
    LRESULT on_push_to_frontend(LPARAM lparam) {
        std::unique_ptr<push_payload> p(reinterpret_cast<push_payload*>(lparam));
        if (!p) return 0;

#ifdef PROXYCLAW_HAS_WEBVIEW2
        if (!webview_) return 0;

        // Compose envelope. p->json_body is already a JSON value (object / array).
        std::string envelope;
        envelope.reserve(p->event.size() + p->json_body.size() + 32);
        envelope.append(R"({"event":")")
                .append(p->event)
                .append(R"(","data":)")
                .append(p->json_body)
                .append(R"(})");

        // UTF-8 → UTF-16 for PostWebMessageAsJson.
        int wlen = MultiByteToWideChar(CP_UTF8, 0, envelope.c_str(),
                                       static_cast<int>(envelope.size()),
                                       nullptr, 0);
        if (wlen <= 0) return 0;
        std::wstring wenvelope(static_cast<size_t>(wlen), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, envelope.c_str(),
                            static_cast<int>(envelope.size()),
                            wenvelope.data(), wlen);

        webview_->PostWebMessageAsJson(wenvelope.c_str());
#endif
        return 0;
    }

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
        if (msg == WM_CREATE) {
            auto* cs  = reinterpret_cast<CREATESTRUCT*>(lparam);
            auto* app = static_cast<webview_app*>(cs->lpCreateParams);
            app->hwnd_ = hwnd;
            app->dpi_ = GetDpiForWindow(hwnd);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
            // Subscribe to the shell's "TaskbarCreated" broadcast so we can
            // re-register the tray icon if the shell is not yet ready when
            // we first try (autostart) or restarts later (Explorer crash).
            app->taskbar_created_msg_ = RegisterWindowMessageW(L"TaskbarCreated");
            return DefWindowProc(hwnd, msg, wparam, lparam);
        }

        // WM_NCCALCSIZE doesn't need an app pointer; handle before the lookup.
        if (msg == WM_NCCALCSIZE && wparam == TRUE) {
            return handle_nccalcsize(reinterpret_cast<NCCALCSIZE_PARAMS*>(lparam));
        }
        // Suppress background erase to prevent white flash.
        if (msg == WM_ERASEBKGND) return 1;

        auto* app = reinterpret_cast<webview_app*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if (!app) return DefWindowProc(hwnd, msg, wparam, lparam);

        // TaskbarCreated is a registered broadcast (id varies per session),
        // so it has to be matched outside the switch.
        if (app->taskbar_created_msg_ != 0 && msg == app->taskbar_created_msg_) {
            PC_LOG_INFO("TaskbarCreated received; re-registering tray icon");
            app->tray_created_     = false;
            app->tray_retry_count_ = 0;
            app->create_tray_icon();
            // Shell is now ready. If the WebView2 controller previously failed
            // (early-logon 0x80070490 on visible autostart), retry now — event-
            // driven, no polling. Tray-only stays lazy: only `failed` recovers,
            // so an unopened tray app doesn't spin up WebView2 here.
            if (app->wv_state_ == wv_state::failed) app->ensure_webview_initialized();
            return 0;
        }

        switch (msg) {
            case WM_NCHITTEST: {
                LRESULT hit = app->handle_nchittest(hwnd, lparam);
                // Fall through to DefWindowProc so WebView2 gets drag regions.
                if (hit != HTCLIENT) return hit;
                break;
            }
            case WM_SIZE:               return app->on_size(wparam);
            case WM_DPICHANGED:         return app->on_dpi_changed(wparam, lparam);
            case WM_MOVE:
#ifdef PROXYCLAW_HAS_WEBVIEW2
                if (app->webview_controller_) app->webview_controller_->NotifyParentWindowPositionChanged();
#endif
                break;
            case WM_CLOSE:              return app->on_close(hwnd);
            case WM_DESTROY:            return app->on_destroy();
            case WM_GETMINMAXINFO:      return on_getminmaxinfo(hwnd, lparam);
            case WM_EXITSIZEMOVE:       return app->on_exitsizemove(hwnd);
            case WM_TRAYICON:           return app->on_trayicon(lparam);
            case WM_COMMAND:            return app->on_command(hwnd, wparam);
            case WM_PUSH_TO_FRONTEND:   return app->on_push_to_frontend(lparam);
            case WM_TIMER:
                if (wparam == TRAY_RETRY_TIMER_ID) {
                    KillTimer(hwnd, TRAY_RETRY_TIMER_ID);
                    app->create_tray_icon();
                    return 0;
                }
                if (wparam == WV_RETRY_TIMER_ID) {
                    KillTimer(hwnd, WV_RETRY_TIMER_ID);
                    // wv_state_ is `failed` here; this re-runs the full init
                    // starting from environment creation.
                    app->ensure_webview_initialized();
                    return 0;
                }
                break;
            default:                    break;
        }
        return DefWindowProc(hwnd, msg, wparam, lparam);
    }

public:
    explicit webview_app(const std::wstring& url, int width = 1200, int height = 800)
        : url_(url), width_(width), height_(height) {}

    ~webview_app() {
        remove_tray_icon();
#ifdef PROXYCLAW_HAS_WEBVIEW2
        webview_controller_.Reset();
        webview_.Reset();
#endif
        if (hwnd_) { DestroyWindow(hwnd_); hwnd_ = nullptr; }
        if (large_icon_) DestroyIcon(large_icon_);
        if (small_icon_) DestroyIcon(small_icon_);
    }

    void set_title(std::wstring_view title) { title_ = title; }
    void set_on_close(std::function<void()> callback) { on_close_ = std::move(callback); }
    void set_on_move_resize(std::function<void(int, int, int, int)> callback) { on_move_resize_ = std::move(callback); }
    void set_initial_rect(int x, int y, int w, int h) { init_x_ = x; init_y_ = y; width_ = w; height_ = h; }
    // Config observers run on API threads; WM_CLOSE reads this on the UI thread.
    void set_close_to_tray(bool v) { close_to_tray_.store(v, std::memory_order_relaxed); }
    void set_devtools_enabled(bool v) { devtools_enabled_ = v; }
    // Skip the initial SW_SHOW and start hidden (tray-only). Used by the
    // "start minimized" autostart sub-toggle. Must be set before run() or
    // the flag is read after window creation and has no effect.
    void set_start_minimized(bool v) { start_minimized_ = v; }
    // Fires on the UI thread when the frontend posts {"type":"ready"} after
    // mount. The callback typically posts a strand task that calls
    // process_projection::replay_to_frontend to deliver the current snapshot.
    void set_on_ready(std::function<void()> callback) { on_ready_ = std::move(callback); }
    // Fired on the UI thread whenever the host transitions WebView2 IsVisible
    // (WM_SIZE minimize/restore + close-to-tray + tray click). Wired in
    // app.cpp to process_projection::set_frontend_visible.
    void set_on_visibility_change(std::function<void(bool)> callback) {
        on_visibility_change_ = std::move(callback);
    }

    // frontend_push_sink — callable from any thread. Marshals onto the UI
    // thread via PostMessageW, where on_push_to_frontend takes ownership
    // of the payload and forwards via PostWebMessageAsJson.
    //
    // Ownership transfer: PostMessageW only adopts the payload on success;
    // on failure we leave it owned by the unique_ptr so its destructor
    // cleans up. release() is therefore conditional on a successful post,
    // not paired with a manual delete on the failure branch.
    void push(std::string_view event, std::string json_body) override {
        if (!hwnd_) return;
        auto p = std::make_unique<push_payload>();
        p->event.assign(event.data(), event.size());
        p->json_body = std::move(json_body);

        if (::PostMessageW(hwnd_, WM_PUSH_TO_FRONTEND, 0,
                           reinterpret_cast<LPARAM>(p.get()))) {
            (void)p.release();
        }
    }

    bool create(HINSTANCE hinstance) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = hinstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        wc.lpszClassName = L"ClewWebViewClass";
        // Embedded icon (resource ID 1 from assets/proxyclaw.rc) — drives the title
        // bar icon (hIconSm) and the Alt-Tab / taskbar big icon (hIcon).
        HICON embedded = LoadIconW(hinstance, MAKEINTRESOURCEW(1));
        wc.hIcon = embedded ? embedded : LoadIcon(nullptr, IDI_APPLICATION);
        wc.hIconSm = wc.hIcon;

        if (!RegisterClassExW(&wc)) {
            DWORD error = GetLastError();
            if (error != ERROR_CLASS_ALREADY_EXISTS) {
                PC_LOG_ERROR("Failed to register window class: {}", error);
                return false;
            }
        }

        int x;
        int y;
        // Saved rectangles remain physical pixels for compatibility. Only an
        // unsaved (centered) initial size is expressed in 96-DPI logical pixels.
        // Negative coordinates are valid for monitors left/above the primary.
        if (!(init_x_ == -1 && init_y_ == -1)) {
            x = init_x_;
            y = init_y_;
        } else {
            UINT dpi = GetDpiForSystem();
            width_ = MulDiv(width_, dpi, 96);
            height_ = MulDiv(height_, dpi, 96);
            int screen_width = GetSystemMetrics(SM_CXSCREEN);
            int screen_height = GetSystemMetrics(SM_CYSCREEN);
            x = (screen_width - width_) / 2;
            y = (screen_height - height_) / 2;
        }

        // A disconnected monitor or a small laptop display must not leave the
        // title bar off screen. Clamp both new and restored rectangles.
        RECT desired = {x, y, x + width_, y + height_};
        MONITORINFO mi = { sizeof(mi) };
        if (GetMonitorInfoW(MonitorFromRect(&desired, MONITOR_DEFAULTTONEAREST), &mi)) {
            width_ = std::min(width_, static_cast<int>(mi.rcWork.right - mi.rcWork.left));
            height_ = std::min(height_, static_cast<int>(mi.rcWork.bottom - mi.rcWork.top));
            x = std::clamp(x, static_cast<int>(mi.rcWork.left), static_cast<int>(mi.rcWork.right) - width_);
            y = std::clamp(y, static_cast<int>(mi.rcWork.top), static_cast<int>(mi.rcWork.bottom) - height_);
        }

        hwnd_ = CreateWindowExW(
            0, L"ClewWebViewClass", title_.c_str(),
            WS_OVERLAPPEDWINDOW,
            x, y, width_, height_,
            nullptr, nullptr, hinstance, this
        );

        if (!hwnd_) {
            PC_LOG_ERROR("Failed to create window: {}", GetLastError());
            return false;
        }
        dpi_ = GetDpiForWindow(hwnd_);
        update_window_icons();

        // Trigger WM_NCCALCSIZE to apply our frameless layout
        SetWindowPos(hwnd_, nullptr, 0, 0, 0, 0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

        // DWM: extend frame into client area for window shadow
        MARGINS margins = {1, 1, 1, 1};
        DwmExtendFrameIntoClientArea(hwnd_, &margins);

        if (start_minimized_) {
            // Reuse the close-to-tray hidden path: SW_HIDE keeps it off the
            // taskbar entirely (SW_MINIMIZE would briefly flash a button).
            // Tray icon is created below, so the user can still bring it up.
            ShowWindow(hwnd_, SW_HIDE);
            currently_visible_ = false;
        } else {
            ShowWindow(hwnd_, SW_SHOW);
            UpdateWindow(hwnd_);
        }
        create_tray_icon();
        if (!start_minimized_) {
            ensure_webview_initialized();  // visible startup: attempt now (after SW_SHOW)
        }
        // tray-only: defer until first show (restore_window) or TaskbarCreated.

        PC_LOG_INFO("WebView window created ({}x{}, frameless, {})",
                    width_, height_, start_minimized_ ? "tray-only" : "visible");
        return true;
    }

    int run() {
        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return static_cast<int>(msg.wParam);
    }

    HWND get_hwnd() const { return hwnd_; }
    bool is_initialized() const { return initialized_; }
    bool is_visible() const { return currently_visible_; }

#ifdef PROXYCLAW_HAS_WEBVIEW2
    // Compares the message's source origin ("scheme://host:port") with the
    // origin of url_. Sub-frames or a page navigated elsewhere are rejected.
    static std::wstring origin_of_url(const std::wstring& url) {
        const auto scheme = url.find(L"://");
        if (scheme == std::wstring::npos) return {};
        std::wstring o = url.substr(0, url.find_first_of(L"/?#", scheme + 3));
        for (auto& c : o) c = static_cast<wchar_t>(towlower(c));
        return o;
    }

    bool message_source_trusted(ICoreWebView2WebMessageReceivedEventArgs* args) const {
        LPWSTR source = nullptr;
        if (FAILED(args->get_Source(&source)) || !source) return false;
        const std::wstring src(source);
        CoTaskMemFree(source);
        const auto expected = origin_of_url(url_);
        return !expected.empty() && origin_of_url(src) == expected;
    }
#endif

    void navigate(const std::wstring& url) {
        url_ = url;
#ifdef PROXYCLAW_HAS_WEBVIEW2
        if (webview_) webview_->Navigate(url.c_str());
#endif
    }

    void execute_script(const std::wstring& script) {
#ifdef PROXYCLAW_HAS_WEBVIEW2
        if (webview_) webview_->ExecuteScript(script.c_str(), nullptr);
#else
        (void)script;
#endif
    }
};

inline bool is_webview2_available() {
#ifdef PROXYCLAW_HAS_WEBVIEW2
    LPWSTR version = nullptr;
    HRESULT hr = GetAvailableCoreWebView2BrowserVersionString(nullptr, &version);
    if (SUCCEEDED(hr) && version) {
        // Proper UTF-16 -> UTF-8 conversion (avoids C4244 narrowing from the
        // iterator-based std::string constructor).
        int len = WideCharToMultiByte(CP_UTF8, 0, version, -1, nullptr, 0, nullptr, nullptr);
        std::string v;
        if (len > 1) {
            v.resize(len - 1);
            WideCharToMultiByte(CP_UTF8, 0, version, -1, v.data(), len, nullptr, nullptr);
        }
        PC_LOG_INFO("WebView2 runtime version: {}", v);
        CoTaskMemFree(version);
        return true;
    }
    PC_LOG_WARN("WebView2 runtime not available.");
    return false;
#else
    PC_LOG_WARN("WebView2 support not compiled in");
    return false;
#endif
}

} // namespace clew
