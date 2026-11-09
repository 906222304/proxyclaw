// An isolated native window: no proxy engine, DNS, configuration, or WebView profile.
#include "ui/webview_app.hpp"
#include <stdexcept>
#include <iostream>

static void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

static int icon_width(HWND hwnd, WPARAM which) {
    auto icon = reinterpret_cast<HICON>(SendMessageW(hwnd, WM_GETICON, which, 0));
    ICONINFO info{};
    check(icon && GetIconInfo(icon, &info), "window icon missing");
    BITMAP bitmap{};
    GetObjectW(info.hbmColor, sizeof(bitmap), &bitmap);
    if (info.hbmColor) DeleteObject(info.hbmColor);
    if (info.hbmMask) DeleteObject(info.hbmMask);
    return bitmap.bmWidth;
}

int main() {
    try {
        check(AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(),
                                         DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2),
              "embedded manifest must activate PerMonitorV2");
        clew::webview_app window(L"about:blank");
        window.set_start_minimized(true);
        window.set_close_to_tray(false);
        check(window.create(GetModuleHandleW(nullptr)), "window creation failed");
        HWND hwnd = window.get_hwnd();
        UINT dpi = GetDpiForWindow(hwnd);
        MONITORINFO monitor{sizeof(monitor)};
        check(GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &monitor),
              "monitor information unavailable");
        RECT rect{};
        GetWindowRect(hwnd, &rect);
        check(rect.left >= monitor.rcWork.left && rect.top >= monitor.rcWork.top &&
                  rect.right <= monitor.rcWork.right && rect.bottom <= monitor.rcWork.bottom,
              "initial window must fit the work area");
        MINMAXINFO limits{};
        SendMessageW(hwnd, WM_GETMINMAXINFO, 0, reinterpret_cast<LPARAM>(&limits));
        check(limits.ptMinTrackSize.x == std::min(MulDiv(900, dpi, 96),
                                                 static_cast<int>(monitor.rcWork.right - monitor.rcWork.left)),
              "minimum width must follow window DPI");
        check(limits.ptMinTrackSize.y == std::min(MulDiv(600, dpi, 96),
                                                 static_cast<int>(monitor.rcWork.bottom - monitor.rcWork.top)),
              "minimum height must follow window DPI");
        check(icon_width(hwnd, ICON_SMALL) == GetSystemMetricsForDpi(SM_CXSMICON, dpi),
              "small icon must use the current DPI");
        // Exercise the handler at several scales without changing Windows settings.
        // Synthetic WM_DPICHANGED checks geometry/icon handling, not a real screen move.
        for (UINT next : {96u, 120u, 144u, 192u}) {
            RECT suggested{monitor.rcWork.left, monitor.rcWork.top,
                           monitor.rcWork.left + limits.ptMinTrackSize.x,
                           monitor.rcWork.top + limits.ptMinTrackSize.y};
            SendMessageW(hwnd, WM_DPICHANGED, MAKEWPARAM(next, next),
                         reinterpret_cast<LPARAM>(&suggested));
            GetWindowRect(hwnd, &rect);
            check(EqualRect(&rect, &suggested), "DPI change must apply the suggested rectangle");
            check(icon_width(hwnd, ICON_SMALL) == GetSystemMetricsForDpi(SM_CXSMICON, next),
                  "small icon must reload at each DPI");
            check(icon_width(hwnd, ICON_BIG) == GetSystemMetricsForDpi(SM_CXICON, next),
                  "large icon must reload at each DPI");
        }
        SendMessageW(hwnd, WM_CLOSE, 0, 0);
        std::cout << "PASS: PerMonitorV2 manifest, work area, DPI minimum size, "
                     "100/125/150/200% resize and icons; actual screen DPI=" << dpi << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
