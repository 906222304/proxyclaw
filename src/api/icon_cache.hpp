#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <gdiplus.h>
#include <appmodel.h>
#include <tlhelp32.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <ranges>
#include <algorithm>
#include <cctype>
#include "core/log.hpp"
#include "core/scoped_exit.hpp"
#include "common/bounded_backoff_cache.hpp"

#pragma comment(lib, "gdiplus.lib")

namespace clew {

class icon_cache {
public:
    bool init() {
        Gdiplus::GdiplusStartupInput input;
        auto status = Gdiplus::GdiplusStartup(&gdiplus_token_, &input, nullptr);
        if (status != Gdiplus::Ok) {
            PC_LOG_ERROR("GDI+ initialization failed: {}", (int)status);
            return false;
        }

        // Cache PNG encoder CLSID
        UINT num = 0;
        UINT size = 0;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size > 0) {
            auto buf = std::make_unique<uint8_t[]>(size);
            auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.get());
            Gdiplus::GetImageEncoders(num, size, encoders);
            for (UINT i = 0; i < num; i++) {
                if (wcscmp(encoders[i].MimeType, L"image/png") == 0) {
                    png_clsid_ = encoders[i].Clsid;
                    has_png_encoder_ = true;
                    break;
                }
            }
        }

        PC_LOG_INFO("Icon cache initialized (GDI+ OK, PNG encoder {})",
                      has_png_encoder_ ? "found" : "NOT found");
        return has_png_encoder_;
    }

    void shutdown() {
        if (gdiplus_token_) {
            Gdiplus::GdiplusShutdown(gdiplus_token_);
            gdiplus_token_ = 0;
        }
    }

    using png_ptr = std::shared_ptr<const std::vector<uint8_t>>;

    // PNG icon for an exe path, or null when it has none. Thread-safe.
    // Keyed by the full (lowercased) path; failures are retried with backoff.
    png_ptr get_icon(std::string_view exe_path) {
        const std::string key = normalize_key(exe_path);
        {
            std::scoped_lock lock(mutex_);
            auto r = icons_.lookup(key, clock::now());
            if (r.s == icons_t::state::hit) return *r.value;
            if (r.s == icons_t::state::negative) return nullptr;
        }

        // Miss: extract outside the lock (Shell + GDI+, a few ms).
        auto png = extract_icon_png(exe_path);
        std::scoped_lock lock(mutex_);
        if (png.empty()) {
            icons_.put_failure(key, clock::now());
            return nullptr;
        }
        return icons_.put(key, std::make_shared<const std::vector<uint8_t>>(std::move(png)));
    }

    // Icon of a running process. The server resolves the image path from
    // the PID (the client never names a path); `exe_name` guards against a
    // reused PID and is the fallback when the process is gone or cannot be
    // opened: a running process with that name is looked up, at most once
    // per backoff period while it keeps failing.
    png_ptr get_icon_for_process(uint32_t pid, std::string_view exe_name) {
        if (pid != 0) {
            auto path = process_image_path(pid);
            if (!path.empty() && (exe_name.empty() || iequals(basename(path), exe_name))) {
                if (!exe_name.empty()) {
                    std::scoped_lock lock(mutex_);
                    names_.put(normalize_key(exe_name), path);
                }
                return get_icon(path);
            }
        }
        if (exe_name.empty()) return nullptr;

        const std::string name_key = normalize_key(exe_name);
        std::string path;
        {
            std::scoped_lock lock(mutex_);
            auto r = names_.lookup(name_key, clock::now());
            if (r.s == names_t::state::negative) return nullptr;
            if (r.s == names_t::state::hit) path = *r.value;
        }
        if (path.empty()) {
            path = find_exe_path(exe_name);  // process snapshot, outside the lock
            std::scoped_lock lock(mutex_);
            if (path.empty()) {
                names_.put_failure(name_key, clock::now());
                return nullptr;
            }
            names_.put(name_key, path);
        }
        return get_icon(path);
    }

    // UTF-8 image path of a running process, empty when it cannot be read.
    static std::string process_image_path(uint32_t pid) {
        auto h = wrap_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!h) return {};
        return exe_path_from_handle(h.get());
    }

private:
    using clock   = std::chrono::steady_clock;
    using icons_t = bounded_backoff_cache<png_ptr>;
    using names_t = bounded_backoff_cache<std::string>;
    // Distinct exe paths seen in one session rarely pass a few hundred.
    static constexpr std::size_t CAPACITY = 512;

    // UI icons occupy 16 CSS pixels. Keep 64 physical pixels in the cache so
    // 125-200% monitors (including additional system text scaling) stay sharp.
    static constexpr int ICON_PIXELS = 64;
    ULONG_PTR gdiplus_token_ = 0;
    CLSID png_clsid_{};
    bool has_png_encoder_ = false;

    std::mutex mutex_;
    icons_t icons_{CAPACITY};  // key: lowercase full path
    names_t names_{CAPACITY};  // key: lowercase exe name -> full path

    [[nodiscard]] static std::string normalize_key(std::string_view path) {
        std::string key{path};
        std::ranges::transform(key, key.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return key;
    }
    [[nodiscard]] static std::string_view basename(std::string_view path) {
        const auto pos = path.find_last_of("\\/");
        return pos == std::string_view::npos ? path : path.substr(pos + 1);
    }
    [[nodiscard]] static bool iequals(std::string_view a, std::string_view b) {
        return a.size() == b.size() &&
               std::ranges::equal(a, b, [](unsigned char x, unsigned char y) {
                   return std::tolower(x) == std::tolower(y);
               });
    }

    // Shell icon APIs (SHGetFileInfo, SHDefExtractIcon) require COM on the
    // calling thread; HTTP worker threads do not initialize it themselves.
    static void ensure_com() {
        struct com_scope {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
            ~com_scope() { if (SUCCEEDED(hr)) CoUninitialize(); }
        };
        thread_local com_scope scope;
        (void)scope;
    }

    // Find exe path by name using CreateToolhelp32Snapshot
    // Get UTF-8 full image path from an opened process handle. Empty on failure.
    static std::string exe_path_from_handle(HANDLE h) {
        WCHAR path[MAX_PATH];
        DWORD len = MAX_PATH;
        if (!QueryFullProcessImageNameW(h, 0, path, &len)) return {};
        int utf8_len = WideCharToMultiByte(CP_UTF8, 0, path, len, nullptr, 0, nullptr, nullptr);
        if (utf8_len <= 0) return {};
        std::string result(utf8_len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, path, len, result.data(), utf8_len, nullptr, nullptr);
        return result;
    }

    static std::string find_exe_path(std::string_view exe_name) {
        // Convert name to wide (use explicit length; string_view is not null-terminated)
        const auto src_len = static_cast<int>(exe_name.size());
        int wlen = MultiByteToWideChar(CP_UTF8, 0, exe_name.data(), src_len, nullptr, 0);
        if (wlen <= 0) return {};
        std::wstring wname(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, exe_name.data(), src_len, wname.data(), wlen);

        // Snapshot processes
        auto snap = wrap_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snap) return {};

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snap.get(), &pe)) return {};

        do {
            if (_wcsicmp(pe.szExeFile, wname.c_str()) != 0) continue;
            auto h = wrap_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                             FALSE, pe.th32ProcessID));
            if (!h) continue;
            auto result = exe_path_from_handle(h.get());
            if (!result.empty()) return result;
        } while (Process32NextW(snap.get(), &pe));

        return {};
    }

    // Extract icon from exe path, convert to PNG bytes
    std::vector<uint8_t> extract_icon_png(std::string_view exe_path) {
        ensure_com();
        // Convert to wide (explicit length; string_view is not null-terminated)
        const auto src_len = static_cast<int>(exe_path.size());
        int wlen = MultiByteToWideChar(CP_UTF8, 0, exe_path.data(), src_len, nullptr, 0);
        if (wlen <= 0) return {};
        std::wstring wpath(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, exe_path.data(), src_len, wpath.data(), wlen);

        // Request an actual high-resolution resource before falling back to
        // Shell's normal large icon; scaling a 16px extraction cannot add detail.
        HICON hIcon = nullptr;
        if (SHDefExtractIconW(wpath.c_str(), 0, 0, &hIcon, nullptr,
                             MAKELONG(ICON_PIXELS, 0)) != S_OK && hIcon) {
            DestroyIcon(hIcon);
            hIcon = nullptr;
        }
        SHFILEINFOW sfi = {};
        if (!hIcon && SHGetFileInfoW(wpath.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON)) {
            hIcon = sfi.hIcon;
        }

        // Fallback: ExtractIconExW
        if (!hIcon) {
            HICON hLarge = nullptr;
            if (ExtractIconExW(wpath.c_str(), 0, &hLarge, nullptr, 1) > 0) {
                hIcon = hLarge;
            }
        }

        if (!hIcon) return {};

        auto png = hicon_to_png(hIcon);
        DestroyIcon(hIcon);
        return png;
    }

    // Convert HICON to PNG bytes via GDI+
    std::vector<uint8_t> hicon_to_png(HICON hIcon) {
        std::vector<uint8_t> result;
        if (!has_png_encoder_) return result;

        std::unique_ptr<Gdiplus::Bitmap> bmp(Gdiplus::Bitmap::FromHICON(hIcon));
        if (!bmp) return result;

        constexpr int SIZE = ICON_PIXELS;
        Gdiplus::Bitmap resized(SIZE, SIZE, PixelFormat32bppARGB);
        {
            Gdiplus::Graphics g(&resized);
            g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
            g.DrawImage(bmp.get(), 0, 0, SIZE, SIZE);
        }

        IStream* stream = nullptr;
        CreateStreamOnHGlobal(nullptr, TRUE, &stream);
        if (stream) {
            if (resized.Save(stream, &png_clsid_, nullptr) == Gdiplus::Ok) {
                LARGE_INTEGER zero = {};
                stream->Seek(zero, STREAM_SEEK_SET, nullptr);
                STATSTG stat;
                stream->Stat(&stat, STATFLAG_NONAME);
                ULONG png_size = (ULONG)stat.cbSize.QuadPart;
                result.resize(png_size);
                ULONG read = 0;
                stream->Read(result.data(), png_size, &read);
                result.resize(read);
            }
            stream->Release();
        }
        return result;
    }
};

} // namespace clew
