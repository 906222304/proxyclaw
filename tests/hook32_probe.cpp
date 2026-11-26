// Minimal 32-bit (x86) TCP probe for live WOW64 hook-mode e2e verification.
//
// Modes:
//   hook32_probe.exe [--child <path>]
//     Waits up to 15 s for proxyclaw_hook32.dll to be injected into this
//     running 32-bit process, performs a blocking TCP connect to 1.1.1.1:80,
//     verifies getpeername() reports the original destination, optionally
//     spawns a 32-bit child with --connect-only (verifying 32->32 import-table
//     injection before its first connect), and prints one JSON line.
//
//   hook32_probe.exe --connect-only
//     Immediately connects to 1.0.0.1:80 without waiting for a sweep; exits 0
//     only if proxyclaw_hook32.dll is already loaded, getpeername() matches
//     1.0.0.1:80, and an HTTP response is received.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

static_assert(sizeof(void*) == 4, "hook32_probe must be built as a 32-bit (x86) binary");

namespace {

bool http_get(const char* ip, uint16_t port, std::string& peer_out) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    DWORD timeout_ms = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(AF_INET, ip, &dst.sin_addr);

    if (connect(s, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) != 0) {
        closesocket(s);
        return false;
    }

    sockaddr_in peer{};
    int peer_len = sizeof(peer);
    if (getpeername(s, reinterpret_cast<sockaddr*>(&peer), &peer_len) == 0) {
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &peer.sin_addr, buf, sizeof(buf));
        peer_out = std::string(buf) + ":" + std::to_string(ntohs(peer.sin_port));
    }

    const std::string req =
        "GET / HTTP/1.0\r\nHost: " + std::string(ip) + "\r\nConnection: close\r\n\r\n";
    if (send(s, req.c_str(), static_cast<int>(req.size()), 0) <= 0) {
        closesocket(s);
        return false;
    }

    char resp[32] = {};
    const int n = recv(s, resp, sizeof(resp) - 1, 0);
    closesocket(s);
    return n >= 5 && std::memcmp(resp, "HTTP/", 5) == 0;
}

int run_child_exe(const wchar_t* child_path) {
    std::wstring cmd = L"\"";
    cmd += child_path;
    cmd += L"\" --connect-only";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(child_path, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        return -1;
    }
    const DWORD wait_rc = WaitForSingleObject(pi.hProcess, 30000);
    DWORD exit_code = 99;
    if (wait_rc == WAIT_OBJECT_0) {
        GetExitCodeProcess(pi.hProcess, &exit_code);
    } else {
        TerminateProcess(pi.hProcess, 98);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(exit_code);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;

    bool connect_only = false;
    const wchar_t* child_path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--connect-only") == 0) {
            connect_only = true;
        } else if (std::wcscmp(argv[i], L"--child") == 0 && i + 1 < argc) {
            child_path = argv[++i];
        }
    }

    if (connect_only) {
        const bool injected = GetModuleHandleW(L"proxyclaw_hook32.dll") != nullptr;
        std::string peer;
        const bool ok = http_get("1.0.0.1", 80, peer);
        WSACleanup();
        return (injected && ok && peer == "1.0.0.1:80") ? 0 : 1;
    }

    bool injected = false;
    for (int i = 0; i < 150; ++i) {
        if (GetModuleHandleW(L"proxyclaw_hook32.dll") != nullptr) {
            injected = true;
            break;
        }
        Sleep(100);
    }

    std::string peer;
    const bool http_ok = http_get("1.1.1.1", 80, peer);
    const int child_rc = child_path ? run_child_exe(child_path) : -2;

    std::printf("{\"arch\":32,\"injected\":%s,\"peer\":\"%s\",\"http\":%s,\"child_rc\":%d}\n",
                injected ? "true" : "false",
                peer.c_str(),
                http_ok ? "true" : "false",
                child_rc);
    std::fflush(stdout);
    WSACleanup();
    return 0;
}
