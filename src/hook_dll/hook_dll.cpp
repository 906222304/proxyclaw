// proxyclaw_hook64.dll: user-mode TCP interception for interception.mode =
// "hook" (see src/hook/hook_mode.hpp for the host side).
//
// Loaded into a proxied process either by the host (CreateRemoteThread +
// LoadLibraryW) or, for a child of an already injected process, through the
// child's import table before its first instruction (Detours
// DetourUpdateProcessWithDll). Once loaded it patches, with Detours:
//
//   ws2_32!connect, WSAConnect   ask the host, then connect to the relay
//   ws2_32!WSAIoctl              hand out a wrapped ConnectEx
//   ws2_32!getpeername           report the original destination
//   ws2_32!closesocket           forget it
//   kernelbase!CreateProcessInternalW   carry the DLL into proxied children
//
// Every failure path falls back to the unmodified call: no host, a timeout,
// an unknown family, anything unexpected means the application connects
// direct exactly as it would without ProxyClaw. UDP is never touched.
//
// Approach after ProxyLane's ProxyLaneHook (MIT, github.com/threatexpert/
// proxyLane); this is an independent, much smaller implementation.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#include <detours.h>

#include <cstring>
#include <new>
#include <unordered_map>

#include "hook/hook_injector.hpp"   // process_is_restricted / _wow64 / _requires_signed_images
#include "hook/hook_protocol.hpp"

using namespace clew::hook;

namespace {

// --- Originals (Detours rewrites these to trampolines) ----------------------

using connect_fn     = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using wsaconnect_fn  = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using wsaioctl_fn    = int (WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using getpeername_fn = int (WSAAPI*)(SOCKET, sockaddr*, int*);
using closesocket_fn = int (WSAAPI*)(SOCKET);
using cpiw_fn        = BOOL (WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                      LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                      LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);

connect_fn     real_connect     = nullptr;
wsaconnect_fn  real_wsaconnect  = nullptr;
wsaioctl_fn    real_wsaioctl    = nullptr;
getpeername_fn real_getpeername = nullptr;
closesocket_fn real_closesocket = nullptr;
cpiw_fn        real_cpiw        = nullptr;
// ConnectEx is not exported: its address comes from WSAIoctl. The function
// body itself is detoured (not the pointer WSAIoctl hands out), so callers
// that fetched the pointer before this DLL arrived -- asyncio's _overlapped,
// .NET and Chromium all cache it at startup -- go through the hook too.
// real_connectex is then the Detours trampoline.
LPFN_CONNECTEX real_connectex = nullptr;
SRWLOCK g_connectex_lock = SRWLOCK_INIT;
bool g_connectex_hooked = false;   // under g_connectex_lock

bool g_installed = false;
char g_dll_ansi[MAX_PATH * 2] = {};   // for DetourUpdateProcessWithDll (LPCSTR only)
thread_local bool t_in_create = false;

// --- Original destinations of redirected sockets (getpeername) -------------

SRWLOCK g_peers_lock = SRWLOCK_INIT;
std::unordered_map<SOCKET, sockaddr_storage>* g_peers = nullptr;   // heap: never destroyed at unload

void remember_peer(SOCKET s, const sockaddr* name, int len) {
    sockaddr_storage ss{};
    std::memcpy(&ss, name, static_cast<size_t>(len) < sizeof(ss) ? static_cast<size_t>(len) : sizeof(ss));
    AcquireSRWLockExclusive(&g_peers_lock);
    if (g_peers) (*g_peers)[s] = ss;
    ReleaseSRWLockExclusive(&g_peers_lock);
}

bool lookup_peer(SOCKET s, sockaddr_storage& out) {
    AcquireSRWLockShared(&g_peers_lock);
    bool found = false;
    if (g_peers) {
        const auto it = g_peers->find(s);
        if (it != g_peers->end()) { out = it->second; found = true; }
    }
    ReleaseSRWLockShared(&g_peers_lock);
    return found;
}

void forget_peer(SOCKET s) {
    AcquireSRWLockExclusive(&g_peers_lock);
    if (g_peers) g_peers->erase(s);
    ReleaseSRWLockExclusive(&g_peers_lock);
}

// --- Host transaction --------------------------------------------------------

bool ask_host(request& req, reply& rep) {
    req.magic = kMagic;
    req.version = kVersion;
    DWORD got = 0;
    const DWORD saved = GetLastError();
    const BOOL ok = CallNamedPipeW(kPipeName, &req, sizeof(req), &rep, sizeof(rep), &got, 1000);
    SetLastError(saved);
    return ok && got == sizeof(rep) && rep.magic == kMagic;
}

// --- Connect rewriting -------------------------------------------------------

enum class route { pass, redirect, block };

struct target {
    bool     v6 = false;        // a real IPv6 destination (not IPv4-mapped)
    uint8_t  addr[16]{};        // network order; IPv4 in [0..3]
    uint16_t port = 0;          // host order
};

bool parse_destination(const sockaddr* name, int len, target& t) {
    if (!name) return false;
    if (name->sa_family == AF_INET && len >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(name);
        std::memcpy(t.addr, &in->sin_addr, 4);
        t.port = ntohs(in->sin_port);
        return true;
    }
    if (name->sa_family == AF_INET6 && len >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(name);
        t.port = ntohs(in6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            std::memcpy(t.addr, &in6->sin6_addr.s6_addr[12], 4);
        } else {
            t.v6 = true;
            std::memcpy(t.addr, &in6->sin6_addr, 16);
        }
        return true;
    }
    return false;
}

bool is_local_destination(const target& t) {
    if (!t.v6) return t.addr[0] == 127 || (t.addr[0] | t.addr[1] | t.addr[2] | t.addr[3]) == 0;
    for (int i = 0; i < 15; ++i) if (t.addr[i]) return false;
    return t.addr[15] <= 1;   // :: and ::1
}

bool is_stream_socket(SOCKET s) {
    int type = 0, len = sizeof(type);
    const int saved = WSAGetLastError();
    const bool ok = getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &len) == 0;
    WSASetLastError(saved);
    return ok && type == SOCK_STREAM;
}

// The socket's local port, binding it to the wildcard address first when the
// application has not bound it (connect would do that implicitly). 0 on error.
uint16_t local_port(SOCKET s, int family, bool may_bind) {
    sockaddr_storage ss{};
    int len = sizeof(ss);
    const int saved = WSAGetLastError();
    if (getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
        if (!may_bind) { WSASetLastError(saved); return 0; }
        sockaddr_storage any{};
        any.ss_family = static_cast<ADDRESS_FAMILY>(family);
        const int any_len = family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        if (bind(s, reinterpret_cast<sockaddr*>(&any), any_len) != 0) { WSASetLastError(saved); return 0; }
        len = sizeof(ss);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len) != 0) { WSASetLastError(saved); return 0; }
    }
    WSASetLastError(saved);
    if (ss.ss_family == AF_INET)  return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
    return 0;
}

// Decide one connect. On redirect, `out` holds the relay address in the
// socket's own family; on block, the WSA error is already set.
route prepare(SOCKET s, const sockaddr* name, int len, bool may_bind,
              sockaddr_storage& out, int& out_len) {
    // A handle value can be reused after a close we did not see (CloseHandle
    // on a socket): whatever this socket was redirected for before is gone.
    forget_peer(s);
    target t;
    if (!parse_destination(name, len, t) || is_local_destination(t)) return route::pass;
    if (!is_stream_socket(s)) return route::pass;
    const uint16_t src = local_port(s, name->sa_family, may_bind);
    if (src == 0) return route::pass;

    request req{};
    req.type = static_cast<uint32_t>(msg_type::connect);
    req.family = t.v6 ? 6 : 4;
    req.dst_port = t.port;
    req.src_port = src;
    std::memcpy(req.dst, t.addr, 16);
    reply rep{};
    if (!ask_host(req, rep)) return route::pass;

    switch (static_cast<verdict>(rep.verdict)) {
    case verdict::block:
        WSASetLastError(rep.error ? static_cast<int>(rep.error) : WSAECONNREFUSED);
        return route::block;
    case verdict::proxy:
        break;
    default:
        return route::pass;
    }
    if (rep.relay_port == 0) return route::pass;

    out = sockaddr_storage{};
    if (name->sa_family == AF_INET) {
        auto* in = reinterpret_cast<sockaddr_in*>(&out);
        in->sin_family = AF_INET;
        in->sin_port = htons(rep.relay_port);
        in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        out_len = sizeof(sockaddr_in);
    } else {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(&out);
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(rep.relay_port);
        if (t.v6) {
            in6->sin6_addr = in6addr_loopback;
        } else {   // dual-stack socket, IPv4 destination: ::ffff:127.0.0.1
            in6->sin6_addr.s6_addr[10] = 0xff;
            in6->sin6_addr.s6_addr[11] = 0xff;
            in6->sin6_addr.s6_addr[12] = 127;
            in6->sin6_addr.s6_addr[15] = 1;
        }
        out_len = sizeof(sockaddr_in6);
    }
    remember_peer(s, name, len);
    return route::redirect;
}

int WSAAPI hook_connect(SOCKET s, const sockaddr* name, int len) {
    sockaddr_storage relay; int relay_len = 0;
    switch (prepare(s, name, len, true, relay, relay_len)) {
    case route::block:    return SOCKET_ERROR;
    case route::redirect: return real_connect(s, reinterpret_cast<sockaddr*>(&relay), relay_len);
    default:              return real_connect(s, name, len);
    }
}

int WSAAPI hook_wsaconnect(SOCKET s, const sockaddr* name, int len, LPWSABUF caller,
                           LPWSABUF callee, LPQOS sqos, LPQOS gqos) {
    sockaddr_storage relay; int relay_len = 0;
    switch (prepare(s, name, len, true, relay, relay_len)) {
    case route::block:    return SOCKET_ERROR;
    case route::redirect:
        return real_wsaconnect(s, reinterpret_cast<sockaddr*>(&relay), relay_len, caller, callee, sqos, gqos);
    default:
        return real_wsaconnect(s, name, len, caller, callee, sqos, gqos);
    }
}

BOOL PASCAL hook_connectex(SOCKET s, const sockaddr* name, int len, PVOID send, DWORD send_len,
                           LPDWORD sent, LPOVERLAPPED ov) {
    sockaddr_storage relay; int relay_len = 0;
    // ConnectEx requires a bound socket; never bind on the caller's behalf.
    switch (prepare(s, name, len, false, relay, relay_len)) {
    case route::block:    return FALSE;
    case route::redirect:
        return real_connectex(s, reinterpret_cast<sockaddr*>(&relay), relay_len, send, send_len, sent, ov);
    default:
        return real_connectex(s, name, len, send, send_len, sent, ov);
    }
}

// Detour the ConnectEx body once. Only the first provider's function is
// hooked (the Microsoft TCP/IP one in practice, shared by IPv4 and IPv6).
void hook_connectex_body(LPFN_CONNECTEX provided) {
    if (!provided || provided == &hook_connectex) return;
    AcquireSRWLockExclusive(&g_connectex_lock);
    if (!g_connectex_hooked) {
        // Attach through real_connectex itself: Detours points it at the
        // trampoline before it writes the jump into the body, so a thread
        // entering hook_connectex never sees it unset.
        real_connectex = provided;
        if (DetourTransactionBegin() == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            if (DetourAttach(reinterpret_cast<PVOID*>(&real_connectex),
                             reinterpret_cast<PVOID>(&hook_connectex)) == NO_ERROR)
                g_connectex_hooked = DetourTransactionCommit() == NO_ERROR;
            else
                DetourTransactionAbort();
        }
    }
    ReleaseSRWLockExclusive(&g_connectex_lock);
}

int WSAAPI hook_wsaioctl(SOCKET s, DWORD code, LPVOID in, DWORD in_len, LPVOID out, DWORD out_len,
                         LPDWORD returned, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    const int r = real_wsaioctl(s, code, in, in_len, out, out_len, returned, ov, cr);
    if (r == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && in && in_len >= sizeof(GUID) &&
        out && out_len >= sizeof(LPFN_CONNECTEX)) {
        static const GUID connectex = WSAID_CONNECTEX;
        if (std::memcmp(in, &connectex, sizeof(GUID)) == 0)
            hook_connectex_body(*static_cast<LPFN_CONNECTEX*>(out));
    }
    return r;
}

// Injected into a running process: it may already hold a ConnectEx pointer.
// The Microsoft provider lives in mswsock.dll, so with mswsock not loaded no
// one can have one yet and the WSAIoctl hook covers the first fetch. Runs on
// its own thread: Winsock calls are not allowed under the loader lock.
DWORD WINAPI prehook_connectex(LPVOID) {
    if (!GetModuleHandleW(L"mswsock.dll")) return 0;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    for (const int af : {AF_INET, AF_INET6}) {
        const SOCKET s = WSASocketW(af, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (s == INVALID_SOCKET) continue;
        GUID guid = WSAID_CONNECTEX;
        LPFN_CONNECTEX fn = nullptr;
        DWORD bytes = 0;
        if (real_wsaioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn, sizeof(fn),
                          &bytes, nullptr, nullptr) == 0)
            hook_connectex_body(fn);
        real_closesocket(s);
    }
    WSACleanup();
    return 0;
}

int WSAAPI hook_getpeername(SOCKET s, sockaddr* name, int* len) {
    const int r = real_getpeername(s, name, len);
    if (r != 0 || !name || !len) return r;
    sockaddr_storage orig;
    if (!lookup_peer(s, orig)) return r;
    const int need = orig.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    if (*len < need) return r;
    std::memcpy(name, &orig, static_cast<size_t>(need));
    *len = need;
    return r;
}

int WSAAPI hook_closesocket(SOCKET s) {
    forget_peer(s);
    return real_closesocket(s);
}

// --- Children ----------------------------------------------------------------

// The child is suspended and has not run: add this DLL to its imports when
// the host says it is proxied and it can actually load it.
void carry_into_child(const PROCESS_INFORMATION& pi) {
    if (!g_dll_ansi[0]) return;
    if (process_is_wow64(pi.hProcess) || process_is_restricted(pi.hProcess) ||
        process_requires_signed_images(pi.hProcess)) return;
    request req{};
    req.type = static_cast<uint32_t>(msg_type::child);
    req.child_pid = pi.dwProcessId;
    reply rep{};
    if (!ask_host(req, rep) || static_cast<verdict>(rep.verdict) != verdict::proxy) return;
    LPCSTR dlls[1] = {g_dll_ansi};
    DetourUpdateProcessWithDll(pi.hProcess, dlls, 1);
}

BOOL WINAPI hook_cpiw(HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                      LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
                      LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi, PHANDLE new_token) {
    // Nested calls (CreateProcessW -> ...Internal) are handled by the outermost.
    if (t_in_create || !pi)
        return real_cpiw(token, app, cmd, pa, ta, inherit, flags, env, dir, si, pi, new_token);
    t_in_create = true;
    const bool add_suspend = (flags & CREATE_SUSPENDED) == 0;
    const BOOL ok = real_cpiw(token, app, cmd, pa, ta, inherit, flags | CREATE_SUSPENDED, env, dir,
                              si, pi, new_token);
    const DWORD err = GetLastError();
    if (ok) {
        carry_into_child(*pi);
        if (add_suspend) ResumeThread(pi->hThread);
    }
    t_in_create = false;
    SetLastError(err);
    return ok;
}

// --- Install -----------------------------------------------------------------

template <typename T>
bool resolve(HMODULE module, const char* name, T& slot) {
    slot = module ? reinterpret_cast<T>(GetProcAddress(module, name)) : nullptr;
    return slot != nullptr;
}

void remember_own_path(HMODULE self) {
    wchar_t wide[MAX_PATH] = {};
    if (!GetModuleFileNameW(self, wide, MAX_PATH)) return;
    BOOL lossy = FALSE;
    if (WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide, -1, g_dll_ansi, sizeof(g_dll_ansi),
                            nullptr, &lossy) && !lossy) return;
    // A path the ANSI code page cannot spell: its 8.3 form usually can.
    wchar_t shortp[MAX_PATH] = {};
    g_dll_ansi[0] = '\0';
    if (GetShortPathNameW(wide, shortp, MAX_PATH) &&
        (!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, shortp, -1, g_dll_ansi,
                              sizeof(g_dll_ansi), nullptr, &lossy) || lossy))
        g_dll_ansi[0] = '\0';
}

void install(HMODULE self) {
    // Loaded a second time under another spelling of its path (8.3 vs long):
    // the first copy already hooks everything.
    if (const HMODULE first = GetModuleHandleW(kDllName); first && first != self) return;
    remember_own_path(self);
    g_peers = new (std::nothrow) std::unordered_map<SOCKET, sockaddr_storage>();
    if (!g_peers) return;

    const HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");   // a static import of this DLL
    const HMODULE kb  = GetModuleHandleW(L"kernelbase.dll");
    if (!resolve(ws2, "connect", real_connect) || !resolve(ws2, "WSAConnect", real_wsaconnect) ||
        !resolve(ws2, "WSAIoctl", real_wsaioctl) || !resolve(ws2, "getpeername", real_getpeername) ||
        !resolve(ws2, "closesocket", real_closesocket))
        return;
    resolve(kb, "CreateProcessInternalW", real_cpiw);   // optional: children

    if (DetourTransactionBegin() != NO_ERROR) return;
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&real_connect), reinterpret_cast<PVOID>(&hook_connect));
    DetourAttach(reinterpret_cast<PVOID*>(&real_wsaconnect), reinterpret_cast<PVOID>(&hook_wsaconnect));
    DetourAttach(reinterpret_cast<PVOID*>(&real_wsaioctl), reinterpret_cast<PVOID>(&hook_wsaioctl));
    DetourAttach(reinterpret_cast<PVOID*>(&real_getpeername), reinterpret_cast<PVOID>(&hook_getpeername));
    DetourAttach(reinterpret_cast<PVOID*>(&real_closesocket), reinterpret_cast<PVOID>(&hook_closesocket));
    if (real_cpiw)
        DetourAttach(reinterpret_cast<PVOID*>(&real_cpiw), reinterpret_cast<PVOID>(&hook_cpiw));
    g_installed = DetourTransactionCommit() == NO_ERROR;
    if (g_installed) {
        if (const HANDLE t = CreateThread(nullptr, 0, &prehook_connectex, nullptr, 0, nullptr))
            CloseHandle(t);
    }
}

} // namespace

// Detours requires an export with ordinal 1 in any DLL it adds to a
// process's import table (DetourUpdateProcessWithDll).
extern "C" void WINAPI proxyclaw_hook_marker() {}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID) {
    if (DetourIsHelperProcess()) return TRUE;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(self);
        // Undo the import-table edit DetourUpdateProcessWithDll made.
        DetourRestoreAfterWith();
        // Pin: the patched entry points jump into this module for the life
        // of the process, so it must never unload.
        HMODULE pinned = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&DllMain), &pinned);
        install(self);
    }
    // Always TRUE: a DLL that fails to load would stop a child from starting.
    return TRUE;
}
