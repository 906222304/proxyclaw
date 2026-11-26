// proxyclaw_hook64.dll: user-mode TCP and UDP interception for
// interception.mode = "hook" (see src/hook/hook_mode.hpp for the host side).
//
// Loaded into a proxied process either by the host (CreateRemoteThread +
// LoadLibraryW) or, for a child of an already injected process, through the
// child's import table before its first instruction (Detours
// DetourUpdateProcessWithDll). Once loaded it patches, with Detours:
//
//   ws2_32!connect, WSAConnect             ask the host, then redirect TCP or
//                                          connected UDP to a loopback relay
//   ws2_32!WSAIoctl                        hook ConnectEx / WSASendMsg / WSARecvMsg
//   ws2_32!sendto, WSASendTo, WSASendMsg   redirect UDP dst to per-flow loopback relay
//   ws2_32!recvfrom, WSARecvFrom,          restore original remote address on inbound
//     WSARecvMsg, WSAGetOverlappedResult,  UDP replies (sync and overlapped/IOCP)
//     kernelbase!GetQueuedCompletionStatus(Ex)
//   ws2_32!getpeername                     report the original destination
//   ws2_32!closesocket                     forget per-socket state / notify UDP close
//   kernelbase!CreateProcessInternalW      carry the DLL into proxied children
//
// Payload bytes are never modified: every proxied UDP flow gets a dedicated
// loopback relay port on the host, so only sockaddr endpoints are rewritten.
// Every failure path falls back to the unmodified call: no host, a timeout,
// an unknown family, or anything unexpected means the application connects
// direct exactly as it would without ProxyClaw.
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

#include <atomic>
#include <cstring>
#include <cwchar>
#include <new>
#include <unordered_map>
#include <vector>

#include "hook/hook_injector.hpp"   // process_is_restricted / _wow64 / _requires_signed_images
#include "hook/hook_protocol.hpp"

using namespace clew::hook;

namespace {

// --- Originals (Detours rewrites these to trampolines) ----------------------

using connect_fn     = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using wsaconnect_fn  = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using wsaioctl_fn    = int (WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using sendto_fn      = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using wsasendto_fn   = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using wsasendmsg_fn  = int (WSAAPI*)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED,
                                     LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using recvfrom_fn    = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using wsarecvfrom_fn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using wsagor_fn      = BOOL (WSAAPI*)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
using getpeername_fn = int (WSAAPI*)(SOCKET, sockaddr*, int*);
using closesocket_fn = int (WSAAPI*)(SOCKET);
using gqcs_fn        = BOOL (WINAPI*)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
using gqcsex_fn      = BOOL (WINAPI*)(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL);
using cpiw_fn        = BOOL (WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                      LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                      LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);

connect_fn     real_connect     = nullptr;
wsaconnect_fn  real_wsaconnect  = nullptr;
wsaioctl_fn    real_wsaioctl    = nullptr;
sendto_fn      real_sendto      = nullptr;
wsasendto_fn   real_wsasendto   = nullptr;
wsasendmsg_fn  real_wsasendmsg  = nullptr;
recvfrom_fn    real_recvfrom    = nullptr;
wsarecvfrom_fn real_wsarecvfrom = nullptr;
wsagor_fn      real_wsagor      = nullptr;
getpeername_fn real_getpeername = nullptr;
closesocket_fn real_closesocket = nullptr;
gqcs_fn        real_gqcs        = nullptr;
gqcsex_fn      real_gqcsex      = nullptr;
cpiw_fn        real_cpiw        = nullptr;

// Extension functions (ConnectEx, WSASendMsg, WSARecvMsg) are fetched via
// WSAIoctl. Their bodies are detoured (not the pointer WSAIoctl hands out), so
// callers that cached pointers before this DLL arrived -- asyncio's _overlapped,
// .NET, Go, Chromium -- go through the hook too.
LPFN_CONNECTEX  real_connectex    = nullptr;
LPFN_WSASENDMSG real_wsasendmsg_x = nullptr;
LPFN_WSARECVMSG real_wsarecvmsg_x = nullptr;
wsasendmsg_fn   orig_wsasendmsg   = nullptr;   // pre-detour ws2_32!WSASendMsg
SRWLOCK g_ext_lock = SRWLOCK_INIT;
bool g_connectex_hooked  = false;   // under g_ext_lock
bool g_wsasendmsg_hooked = false;   // under g_ext_lock
bool g_wsarecvmsg_hooked = false;   // under g_ext_lock

bool g_installed = false;
char g_dll_ansi[MAX_PATH * 2] = {};     // own DLL path for DetourUpdateProcessWithDll (LPCSTR)
bool g_sibling_dll_exists = false;      // sibling 32/64-bit DLL exists for DetourProcessViaHelperW
thread_local bool t_in_create = false;

// --- Shared endpoint helpers ------------------------------------------------

enum class route { pass, redirect, block };

struct target {
    bool     v6 = false;        // a real IPv6 destination (not IPv4-mapped)
    uint8_t  addr[16]{};        // network order; IPv4 in [0..3]
    uint16_t port = 0;          // host order
};

bool target_equal(const target& a, const target& b) {
    if (a.v6 != b.v6 || a.port != b.port) return false;
    return std::memcmp(a.addr, b.addr, a.v6 ? 16 : 4) == 0;
}

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

// --- UDP route cache, reverse endpoint map, and pending overlapped recvs ----
// Lock order (strict, never inverted): g_pending_lock -> g_udp_lock.

constexpr ULONGLONG kUdpRouteTtlMs     = 15000;
constexpr size_t    kMaxRoutesPerSock  = 64;
constexpr size_t    kMaxReverseEntries = 4096;
constexpr size_t    kMaxPendingRecv    = 16384;

struct udp_route_entry {
    target    dst{};
    route     verdict = route::pass;
    uint16_t  relay_port = 0;
    int       block_err = 0;
    ULONGLONG expires_ms = 0;
};

struct udp_socket_state {
    uint16_t src_port = 0;
    uint8_t  used_families = 0;   // bit 0: v4 proxied, bit 1: v6 proxied
    std::vector<udp_route_entry> routes;
};

struct udp_reverse_entry {
    SOCKET    owner = INVALID_SOCKET;
    target    orig{};
    ULONGLONG touched_ms = 0;
};

struct pending_recv {
    SOCKET    sock = INVALID_SOCKET;
    sockaddr* from = nullptr;
    int*      from_len = nullptr;
};

SRWLOCK g_udp_lock = SRWLOCK_INIT;
std::unordered_map<SOCKET, udp_socket_state>*     g_udp_routes  = nullptr;   // heap: never destroyed
std::unordered_map<uint32_t, udp_reverse_entry>*  g_udp_reverse = nullptr;   // key: (v6<<16)|relay_port

SRWLOCK g_pending_lock = SRWLOCK_INIT;
std::unordered_map<LPOVERLAPPED, pending_recv>*   g_pending_recv = nullptr;  // heap: never destroyed
std::atomic<size_t> g_pending_recv_count{0};

uint32_t reverse_key(bool v6, uint16_t port) {
    return (v6 ? 0x10000u : 0u) | port;
}

bool lookup_udp_route(SOCKET s, uint16_t cur_port, const target& dst, ULONGLONG now,
                      udp_route_entry& out) {
    bool found = false;
    bool stale_handle = false;
    AcquireSRWLockShared(&g_udp_lock);
    if (g_udp_routes) {
        const auto it = g_udp_routes->find(s);
        if (it != g_udp_routes->end()) {
            if (cur_port == 0 || it->second.src_port != cur_port) {
                stale_handle = true;
            } else {
                for (const auto& r : it->second.routes) {
                    if (target_equal(r.dst, dst)) {
                        if (now < r.expires_ms) {
                            out = r;
                            found = true;
                        }
                        break;
                    }
                }
            }
        }
    }
    ReleaseSRWLockShared(&g_udp_lock);

    if (stale_handle) {
        // Socket handle value was reused after CloseHandle: drop old routes.
        AcquireSRWLockExclusive(&g_udp_lock);
        if (g_udp_routes) {
            const auto it = g_udp_routes->find(s);
            if (it != g_udp_routes->end() && (cur_port == 0 || it->second.src_port != cur_port)) {
                g_udp_routes->erase(it);
                if (g_udp_reverse) {
                    for (auto rit = g_udp_reverse->begin(); rit != g_udp_reverse->end(); ) {
                        if (rit->second.owner == s) rit = g_udp_reverse->erase(rit);
                        else ++rit;
                    }
                }
            }
        }
        ReleaseSRWLockExclusive(&g_udp_lock);
    }
    return found;
}

void store_udp_route(SOCKET s, uint16_t src_port, const target& dst, route v,
                     uint16_t relay_port, int block_err, ULONGLONG now) {
    AcquireSRWLockExclusive(&g_udp_lock);
    if (g_udp_routes) {
        auto& st = (*g_udp_routes)[s];
        if (st.src_port != 0 && st.src_port != src_port) {
            st.routes.clear();
            st.used_families = 0;
        }
        st.src_port = src_port;
        if (v == route::redirect) {
            st.used_families |= dst.v6 ? 2u : 1u;
        }
        const udp_route_entry entry{dst, v, relay_port, block_err, now + kUdpRouteTtlMs};
        bool updated = false;
        for (auto& existing : st.routes) {
            if (target_equal(existing.dst, dst)) {
                existing = entry;
                updated = true;
                break;
            }
        }
        if (!updated) {
            if (st.routes.size() >= kMaxRoutesPerSock) {
                // Evict the entry expiring soonest.
                size_t victim = 0;
                for (size_t i = 1; i < st.routes.size(); ++i) {
                    if (st.routes[i].expires_ms < st.routes[victim].expires_ms) victim = i;
                }
                st.routes[victim] = entry;
            } else {
                st.routes.push_back(entry);
            }
        }
    }
    if (v == route::redirect && relay_port != 0 && g_udp_reverse) {
        const uint32_t k = reverse_key(dst.v6, relay_port);
        if (g_udp_reverse->find(k) == g_udp_reverse->end() &&
            g_udp_reverse->size() >= kMaxReverseEntries) {
            auto oldest = g_udp_reverse->begin();
            for (auto it = g_udp_reverse->begin(); it != g_udp_reverse->end(); ++it) {
                if (it->second.touched_ms < oldest->second.touched_ms) oldest = it;
            }
            if (oldest != g_udp_reverse->end()) g_udp_reverse->erase(oldest);
        }
        (*g_udp_reverse)[k] = udp_reverse_entry{s, dst, now};
    }
    ReleaseSRWLockExclusive(&g_udp_lock);
}

bool lookup_udp_reverse(bool v6, uint16_t relay_port, target& out) {
    bool found = false;
    AcquireSRWLockShared(&g_udp_lock);
    if (g_udp_reverse) {
        const auto it = g_udp_reverse->find(reverse_key(v6, relay_port));
        if (it != g_udp_reverse->end()) {
            out = it->second.orig;
            found = true;
        }
    }
    ReleaseSRWLockShared(&g_udp_lock);
    return found;
}

bool forget_udp_socket(SOCKET s, uint16_t& out_port, uint16_t& out_family) {
    out_port = 0;
    out_family = 0;
    bool had_proxied = false;
    AcquireSRWLockExclusive(&g_udp_lock);
    if (g_udp_routes) {
        const auto it = g_udp_routes->find(s);
        if (it != g_udp_routes->end()) {
            if (it->second.used_families != 0 && it->second.src_port != 0) {
                had_proxied = true;
                out_port = it->second.src_port;
                out_family = (it->second.used_families == 1u) ? 4
                           : (it->second.used_families == 2u) ? 6
                           : 0;
            }
            g_udp_routes->erase(it);
        }
    }
    if (had_proxied && g_udp_reverse) {
        for (auto it = g_udp_reverse->begin(); it != g_udp_reverse->end(); ) {
            if (it->second.owner == s) it = g_udp_reverse->erase(it);
            else ++it;
        }
    }
    ReleaseSRWLockExclusive(&g_udp_lock);
    return had_proxied;
}

// Rewrite a loopback relay source address returned by recvfrom / WSARecvFrom /
// WSARecvMsg back to the original remote destination. Idempotent: calling it
// on an already-rewritten or non-loopback address is a fast no-op.
void rewrite_udp_from(sockaddr* from, int* from_len) {
    if (!from || !from_len) return;
    bool v6 = false;
    bool mapped_v4_in_v6 = false;
    uint16_t port = 0;

    if (from->sa_family == AF_INET && *from_len >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(from);
        if ((ntohl(in->sin_addr.s_addr) >> 24) != 127) return;
        port = ntohs(in->sin_port);
    } else if (from->sa_family == AF_INET6 && *from_len >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(from);
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            if (in6->sin6_addr.s6_addr[12] != 127) return;
            mapped_v4_in_v6 = true;
            port = ntohs(in6->sin6_port);
        } else if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) {
            v6 = true;
            port = ntohs(in6->sin6_port);
        } else {
            return;
        }
    } else {
        return;
    }
    if (port == 0) return;

    target orig{};
    if (!lookup_udp_reverse(v6, port, orig)) return;

    if (from->sa_family == AF_INET) {
        if (orig.v6) return;
        auto* in = reinterpret_cast<sockaddr_in*>(from);
        std::memcpy(&in->sin_addr, orig.addr, 4);
        in->sin_port = htons(orig.port);
    } else if (from->sa_family == AF_INET6) {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(from);
        in6->sin6_port = htons(orig.port);
        in6->sin6_scope_id = 0;
        if (mapped_v4_in_v6 || !orig.v6) {
            std::memset(&in6->sin6_addr, 0, sizeof(in6->sin6_addr));
            in6->sin6_addr.s6_addr[10] = 0xff;
            in6->sin6_addr.s6_addr[11] = 0xff;
            std::memcpy(&in6->sin6_addr.s6_addr[12], orig.addr, 4);
        } else {
            std::memcpy(&in6->sin6_addr, orig.addr, 16);
        }
    }
}

void register_pending_recv(LPOVERLAPPED ov, SOCKET s, sockaddr* from, int* from_len) {
    if (!ov || !from || !from_len) return;
    AcquireSRWLockExclusive(&g_pending_lock);
    if (g_pending_recv && g_pending_recv->size() < kMaxPendingRecv) {
        (*g_pending_recv)[ov] = pending_recv{s, from, from_len};
        g_pending_recv_count.store(g_pending_recv->size(), std::memory_order_relaxed);
    }
    ReleaseSRWLockExclusive(&g_pending_lock);
}

// Atomically pop `ov` and (when rewrite is true) rewrite its sockaddr before
// releasing g_pending_lock, preventing a race between synchronous WSARecvFrom
// return and a concurrent IOCP worker completing the same OVERLAPPED.
void complete_pending_recv(LPOVERLAPPED ov, bool rewrite) {
    if (!ov) return;
    AcquireSRWLockExclusive(&g_pending_lock);
    if (g_pending_recv) {
        const auto it = g_pending_recv->find(ov);
        if (it != g_pending_recv->end()) {
            const pending_recv pr = it->second;
            g_pending_recv->erase(it);
            g_pending_recv_count.store(g_pending_recv->size(), std::memory_order_relaxed);
            if (rewrite) rewrite_udp_from(pr.from, pr.from_len);
        }
    }
    ReleaseSRWLockExclusive(&g_pending_lock);
}

void forget_pending_recv_for_socket(SOCKET s) {
    if (g_pending_recv_count.load(std::memory_order_relaxed) == 0) return;
    AcquireSRWLockExclusive(&g_pending_lock);
    if (g_pending_recv) {
        for (auto it = g_pending_recv->begin(); it != g_pending_recv->end(); ) {
            if (it->second.sock == s) it = g_pending_recv->erase(it);
            else ++it;
        }
        g_pending_recv_count.store(g_pending_recv->size(), std::memory_order_relaxed);
    }
    ReleaseSRWLockExclusive(&g_pending_lock);
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

// --- Connect & UDP send rewriting -------------------------------------------

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

bool is_unroutable_udp_destination(const target& t) {
    if (is_local_destination(t)) return true;
    if (!t.v6) {
        // Multicast 224.0.0.0/4 and limited broadcast 255.255.255.255.
        if ((t.addr[0] & 0xF0u) == 0xE0u) return true;
        if ((t.addr[0] & t.addr[1] & t.addr[2] & t.addr[3]) == 0xFFu) return true;
        return false;
    }
    // IPv6 multicast ff00::/8 and link-local fe80::/10.
    return t.addr[0] == 0xFFu || (t.addr[0] == 0xFEu && (t.addr[1] & 0xC0u) == 0x80u);
}

int socket_type(SOCKET s) {
    int type = 0, len = sizeof(type);
    const int saved = WSAGetLastError();
    const bool ok = getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &len) == 0;
    WSASetLastError(saved);
    return ok ? type : 0;
}

// Connecting or sending from a socket bound to a specific non-loopback NIC IP
// to 127.0.0.1 / ::1 fails on Windows (WSAEADDRNOTAVAIL / WSAEINVAL). Only
// wildcard or loopback-bound sockets can be redirected to the local relay.
bool bound_can_reach_loopback(const sockaddr_storage& ss, bool dst_v6) {
    if (ss.ss_family == AF_INET) {
        const uint32_t ip = ntohl(reinterpret_cast<const sockaddr_in*>(&ss)->sin_addr.s_addr);
        return ip == INADDR_ANY || (ip >> 24) == 127;
    }
    if (ss.ss_family == AF_INET6) {
        const auto& a = reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_addr;
        if (IN6_IS_ADDR_UNSPECIFIED(&a)) return true;
        if (dst_v6) return IN6_IS_ADDR_LOOPBACK(&a);
        return IN6_IS_ADDR_V4MAPPED(&a) &&
               (a.s6_addr[12] == 127 ||
                (a.s6_addr[12] | a.s6_addr[13] | a.s6_addr[14] | a.s6_addr[15]) == 0);
    }
    return false;
}

// The socket's local port, binding it to the wildcard address first when the
// application has not bound it (connect / sendto would do that implicitly).
// 0 on error or when the socket is pinned to a non-loopback interface address.
uint16_t local_port(SOCKET s, int family, bool dst_v6, bool may_bind) {
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
    if (!bound_can_reach_loopback(ss, dst_v6)) return 0;
    if (ss.ss_family == AF_INET)  return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
    return 0;
}

void fill_loopback_sockaddr(int sa_family, bool dst_v6, uint16_t relay_port,
                            sockaddr_storage& out, int& out_len) {
    out = sockaddr_storage{};
    if (sa_family == AF_INET) {
        auto* in = reinterpret_cast<sockaddr_in*>(&out);
        in->sin_family = AF_INET;
        in->sin_port = htons(relay_port);
        in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        out_len = sizeof(sockaddr_in);
    } else {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(&out);
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(relay_port);
        if (dst_v6) {
            in6->sin6_addr = in6addr_loopback;
        } else {   // dual-stack socket, IPv4 destination: ::ffff:127.0.0.1
            in6->sin6_addr.s6_addr[10] = 0xff;
            in6->sin6_addr.s6_addr[11] = 0xff;
            in6->sin6_addr.s6_addr[12] = 127;
            in6->sin6_addr.s6_addr[15] = 1;
        }
        out_len = sizeof(sockaddr_in6);
    }
}

// Decide one UDP sendto/WSASendTo/WSASendMsg or connected-UDP connect.
// Uses a short-TTL per-socket route cache to keep hot UDP paths off the pipe.
route prepare_udp(SOCKET s, const sockaddr* name, int len, bool may_bind,
                  sockaddr_storage& out, int& out_len) {
    target t;
    if (!parse_destination(name, len, t) || t.port == 0 || is_unroutable_udp_destination(t))
        return route::pass;
    if (socket_type(s) != SOCK_DGRAM) return route::pass;

    const uint16_t src = local_port(s, name->sa_family, t.v6, may_bind);
    if (src == 0) return route::pass;

    const ULONGLONG now = GetTickCount64();
    udp_route_entry cached{};
    if (lookup_udp_route(s, src, t, now, cached)) {
        if (cached.verdict == route::block) {
            WSASetLastError(cached.block_err ? cached.block_err : WSAENETUNREACH);
            return route::block;
        }
        if (cached.verdict == route::redirect && cached.relay_port != 0) {
            fill_loopback_sockaddr(name->sa_family, t.v6, cached.relay_port, out, out_len);
            return route::redirect;
        }
        return route::pass;
    }

    request req{};
    req.type = static_cast<uint32_t>(msg_type::udp_send);
    req.family = t.v6 ? 6 : 4;
    req.dst_port = t.port;
    req.src_port = src;
    std::memcpy(req.dst, t.addr, 16);
    reply rep{};
    if (!ask_host(req, rep)) return route::pass;

    switch (static_cast<verdict>(rep.verdict)) {
    case verdict::block: {
        const int err = rep.error ? static_cast<int>(rep.error) : WSAENETUNREACH;
        store_udp_route(s, src, t, route::block, 0, err, now);
        WSASetLastError(err);
        return route::block;
    }
    case verdict::proxy:
        if (rep.relay_port == 0) return route::pass;
        store_udp_route(s, src, t, route::redirect, rep.relay_port, 0, now);
        fill_loopback_sockaddr(name->sa_family, t.v6, rep.relay_port, out, out_len);
        return route::redirect;
    default:
        store_udp_route(s, src, t, route::pass, 0, 0, now);
        return route::pass;
    }
}

// Decide one connect / WSAConnect / ConnectEx. On redirect, `out` holds the
// relay address in the socket's own family; on block, the WSA error is set.
route prepare(SOCKET s, const sockaddr* name, int len, bool may_bind,
              sockaddr_storage& out, int& out_len) {
    // A handle value can be reused after a close we did not see (CloseHandle
    // on a socket): whatever this socket was redirected for before is gone.
    forget_peer(s);
    target t;
    if (!parse_destination(name, len, t) || is_local_destination(t)) return route::pass;
    const int stype = socket_type(s);
    if (stype == SOCK_DGRAM) {
        if (!may_bind) return route::pass;
        const route r = prepare_udp(s, name, len, may_bind, out, out_len);
        if (r == route::redirect) remember_peer(s, name, len);
        return r;
    }
    if (stype != SOCK_STREAM) return route::pass;
    const uint16_t src = local_port(s, name->sa_family, t.v6, may_bind);
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

    fill_loopback_sockaddr(name->sa_family, t.v6, rep.relay_port, out, out_len);
    remember_peer(s, name, len);
    return route::redirect;
}

bool wsamsg_pins_non_loopback(const WSAMSG* msg) {
    if (!msg || !msg->Control.buf || msg->Control.len == 0) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(msg->Control.buf);
    const size_t total = msg->Control.len;
    size_t off = 0;
    auto align_up = [](size_t n) -> size_t {
        constexpr size_t a = sizeof(SIZE_T);
        return (n + a - 1) & ~(a - 1);
    };
    while (off + sizeof(WSACMSGHDR) <= total) {
        const auto* hdr = reinterpret_cast<const WSACMSGHDR*>(base + off);
        if (hdr->cmsg_len < sizeof(WSACMSGHDR) || hdr->cmsg_len > total - off) break;
        const size_t data_off = align_up(sizeof(WSACMSGHDR));
        if (hdr->cmsg_len > data_off) {
            const uint8_t* data = base + off + data_off;
            const size_t data_len = hdr->cmsg_len - data_off;
            if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_PKTINFO &&
                data_len >= sizeof(IN_PKTINFO)) {
                IN_PKTINFO pi{};
                std::memcpy(&pi, data, sizeof(pi));
                const uint32_t ip = ntohl(pi.ipi_addr.s_addr);
                if (ip != INADDR_ANY && (ip >> 24) != 127) return true;
            } else if (hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_PKTINFO &&
                       data_len >= sizeof(IN6_PKTINFO)) {
                IN6_PKTINFO pi6{};
                std::memcpy(&pi6, data, sizeof(pi6));
                if (!IN6_IS_ADDR_UNSPECIFIED(&pi6.ipi6_addr) &&
                    !IN6_IS_ADDR_LOOPBACK(&pi6.ipi6_addr)) {
                    return true;
                }
            }
        }
        const size_t step = align_up(hdr->cmsg_len);
        if (step == 0 || step > total - off) break;
        off += step;
    }
    return false;
}

// --- Winsock & IOCP hook entry points ---------------------------------------

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

int WSAAPI hook_sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    if (!to || tolen <= 0) return real_sendto(s, buf, len, flags, to, tolen);
    sockaddr_storage relay; int relay_len = 0;
    switch (prepare_udp(s, to, tolen, true, relay, relay_len)) {
    case route::block:    return SOCKET_ERROR;
    case route::redirect:
        return real_sendto(s, buf, len, flags, reinterpret_cast<sockaddr*>(&relay), relay_len);
    default:
        return real_sendto(s, buf, len, flags, to, tolen);
    }
}

int WSAAPI hook_wsasendto(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
                          const sockaddr* to, int tolen, LPWSAOVERLAPPED ov,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (!to || tolen <= 0)
        return real_wsasendto(s, buffers, count, sent, flags, to, tolen, ov, cr);
    sockaddr_storage relay; int relay_len = 0;
    switch (prepare_udp(s, to, tolen, true, relay, relay_len)) {
    case route::block:    return SOCKET_ERROR;
    case route::redirect:
        return real_wsasendto(s, buffers, count, sent, flags,
                              reinterpret_cast<sockaddr*>(&relay), relay_len, ov, cr);
    default:
        return real_wsasendto(s, buffers, count, sent, flags, to, tolen, ov, cr);
    }
}

int call_wsasendmsg_hook(LPFN_WSASENDMSG real_fn, SOCKET s, LPWSAMSG msg, DWORD flags,
                         LPDWORD sent, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (!msg || !msg->name || msg->namelen <= 0 || wsamsg_pins_non_loopback(msg))
        return real_fn(s, msg, flags, sent, ov, cr);
    sockaddr_storage relay; int relay_len = 0;
    switch (prepare_udp(s, msg->name, msg->namelen, true, relay, relay_len)) {
    case route::block:    return SOCKET_ERROR;
    case route::redirect: {
        WSAMSG copy = *msg;
        copy.name = reinterpret_cast<LPSOCKADDR>(&relay);
        copy.namelen = relay_len;
        return real_fn(s, &copy, flags, sent, ov, cr);
    }
    default:
        return real_fn(s, msg, flags, sent, ov, cr);
    }
}

int WSAAPI hook_wsasendmsg(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD sent,
                           LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    return call_wsasendmsg_hook(real_wsasendmsg, s, msg, flags, sent, ov, cr);
}

int PASCAL hook_wsasendmsg_ext(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD sent,
                               LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    return call_wsasendmsg_hook(real_wsasendmsg_x, s, msg, flags, sent, ov, cr);
}

int WSAAPI hook_recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen) {
    const int r = real_recvfrom(s, buf, len, flags, from, fromlen);
    const int err = WSAGetLastError();
    if ((r != SOCKET_ERROR || err == WSAEMSGSIZE) && from && fromlen) {
        rewrite_udp_from(from, fromlen);
    }
    WSASetLastError(err);
    return r;
}

int WSAAPI hook_wsarecvfrom(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD recvd,
                            LPDWORD flags, sockaddr* from, LPINT fromlen,
                            LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (!from || !fromlen)
        return real_wsarecvfrom(s, buffers, count, recvd, flags, from, fromlen, ov, cr);
    if (!ov) {
        const int r = real_wsarecvfrom(s, buffers, count, recvd, flags, from, fromlen, ov, cr);
        const int err = WSAGetLastError();
        if (r == 0 || err == WSAEMSGSIZE) rewrite_udp_from(from, fromlen);
        WSASetLastError(err);
        return r;
    }
    if (!cr) register_pending_recv(ov, s, from, fromlen);
    const int r = real_wsarecvfrom(s, buffers, count, recvd, flags, from, fromlen, ov, cr);
    const int err = WSAGetLastError();
    if (!cr) {
        if (r == 0 || err == WSAEMSGSIZE) complete_pending_recv(ov, true);
        else if (err != WSA_IO_PENDING)   complete_pending_recv(ov, false);
    } else if (r == 0 || err == WSAEMSGSIZE) {
        rewrite_udp_from(from, fromlen);
    }
    WSASetLastError(err);
    return r;
}

int PASCAL hook_wsarecvmsg_ext(SOCKET s, LPWSAMSG msg, LPDWORD recvd, LPWSAOVERLAPPED ov,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (!msg || !msg->name || msg->namelen <= 0)
        return real_wsarecvmsg_x(s, msg, recvd, ov, cr);
    if (!ov) {
        const int r = real_wsarecvmsg_x(s, msg, recvd, ov, cr);
        const int err = WSAGetLastError();
        if (r == 0 || err == WSAEMSGSIZE) rewrite_udp_from(msg->name, &msg->namelen);
        WSASetLastError(err);
        return r;
    }
    if (!cr) register_pending_recv(ov, s, msg->name, &msg->namelen);
    const int r = real_wsarecvmsg_x(s, msg, recvd, ov, cr);
    const int err = WSAGetLastError();
    if (!cr) {
        if (r == 0 || err == WSAEMSGSIZE) complete_pending_recv(ov, true);
        else if (err != WSA_IO_PENDING)   complete_pending_recv(ov, false);
    } else if (r == 0 || err == WSAEMSGSIZE) {
        rewrite_udp_from(msg->name, &msg->namelen);
    }
    WSASetLastError(err);
    return r;
}

BOOL WSAAPI hook_wsagor(SOCKET s, LPWSAOVERLAPPED ov, LPDWORD transfer, BOOL wait, LPDWORD flags) {
    const BOOL ok = real_wsagor(s, ov, transfer, wait, flags);
    if (ov && g_pending_recv_count.load(std::memory_order_relaxed) != 0) {
        const int err = WSAGetLastError();
        if (ok || err == WSAEMSGSIZE) {
            complete_pending_recv(ov, true);
        } else if (err != WSA_IO_INCOMPLETE) {
            complete_pending_recv(ov, false);
        }
        WSASetLastError(err);
    }
    return ok;
}

BOOL WINAPI hook_gqcs(HANDLE port, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED* ov, DWORD timeout) {
    const BOOL ok = real_gqcs(port, bytes, key, ov, timeout);
    if (ov && *ov && g_pending_recv_count.load(std::memory_order_relaxed) != 0) {
        const DWORD err = GetLastError();
        complete_pending_recv(*ov, ok != FALSE || err == ERROR_MORE_DATA);
        SetLastError(err);
    }
    return ok;
}

BOOL WINAPI hook_gqcsex(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count, PULONG removed,
                        DWORD timeout, BOOL alertable) {
    const BOOL ok = real_gqcsex(port, entries, count, removed, timeout, alertable);
    if (ok && entries && removed && *removed > 0 &&
        g_pending_recv_count.load(std::memory_order_relaxed) != 0) {
        const DWORD err = GetLastError();
        for (ULONG i = 0; i < *removed; ++i) {
            if (entries[i].lpOverlapped) {
                const ULONG status = static_cast<ULONG>(entries[i].Internal);
                // NT_SUCCESS(status) or STATUS_BUFFER_OVERFLOW (0x80000005).
                const bool rewrite = static_cast<LONG>(status) >= 0 || status == 0x80000005u;
                complete_pending_recv(entries[i].lpOverlapped, rewrite);
            }
        }
        SetLastError(err);
    }
    return ok;
}

// Detour one mswsock extension function body once.
template <typename Fn>
void hook_extension_body(Fn provided, Fn& real_slot, Fn hook_fn, bool& hooked_flag,
                         Fn skip_alt = nullptr) {
    if (!provided || provided == hook_fn || (skip_alt && provided == skip_alt)) return;
    AcquireSRWLockExclusive(&g_ext_lock);
    if (!hooked_flag) {
        // Attach through real_slot itself: Detours points it at the trampoline
        // before it writes the jump into the body, so a thread entering hook_fn
        // never sees it unset.
        real_slot = provided;
        if (DetourTransactionBegin() == NO_ERROR) {
            DetourUpdateThread(GetCurrentThread());
            if (DetourAttach(reinterpret_cast<PVOID*>(&real_slot),
                             reinterpret_cast<PVOID>(hook_fn)) == NO_ERROR)
                hooked_flag = DetourTransactionCommit() == NO_ERROR;
            else
                DetourTransactionAbort();
        }
    }
    ReleaseSRWLockExclusive(&g_ext_lock);
}

int WSAAPI hook_wsaioctl(SOCKET s, DWORD code, LPVOID in, DWORD in_len, LPVOID out, DWORD out_len,
                         LPDWORD returned, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    const int r = real_wsaioctl(s, code, in, in_len, out, out_len, returned, ov, cr);
    if (r == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && in && in_len >= sizeof(GUID) &&
        out && out_len >= sizeof(PVOID)) {
        static const GUID guid_connectex  = WSAID_CONNECTEX;
        static const GUID guid_wsasendmsg = WSAID_WSASENDMSG;
        static const GUID guid_wsarecvmsg = WSAID_WSARECVMSG;
        if (std::memcmp(in, &guid_connectex, sizeof(GUID)) == 0) {
            hook_extension_body(*static_cast<LPFN_CONNECTEX*>(out), real_connectex,
                                &hook_connectex, g_connectex_hooked);
        } else if (std::memcmp(in, &guid_wsasendmsg, sizeof(GUID)) == 0) {
            hook_extension_body(*static_cast<LPFN_WSASENDMSG*>(out), real_wsasendmsg_x,
                                &hook_wsasendmsg_ext, g_wsasendmsg_hooked,
                                static_cast<LPFN_WSASENDMSG>(orig_wsasendmsg));
        } else if (std::memcmp(in, &guid_wsarecvmsg, sizeof(GUID)) == 0) {
            hook_extension_body(*static_cast<LPFN_WSARECVMSG*>(out), real_wsarecvmsg_x,
                                &hook_wsarecvmsg_ext, g_wsarecvmsg_hooked);
        }
    }
    return r;
}

// Injected into a running process: it may already hold cached ConnectEx /
// WSASendMsg / WSARecvMsg pointers. The Microsoft provider lives in
// mswsock.dll, so with mswsock not loaded no one can have one yet and the
// WSAIoctl hook covers the first fetch. Runs on its own thread: Winsock calls
// are not allowed under the loader lock.
DWORD WINAPI prehook_extensions(LPVOID) {
    if (!GetModuleHandleW(L"mswsock.dll")) return 0;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    for (const int af : {AF_INET, AF_INET6}) {
        const SOCKET ts = WSASocketW(af, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (ts != INVALID_SOCKET) {
            GUID guid = WSAID_CONNECTEX;
            LPFN_CONNECTEX fn = nullptr;
            DWORD bytes = 0;
            if (real_wsaioctl(ts, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                              &fn, sizeof(fn), &bytes, nullptr, nullptr) == 0) {
                hook_extension_body(fn, real_connectex, &hook_connectex, g_connectex_hooked);
            }
            real_closesocket(ts);
        }
        const SOCKET us = WSASocketW(af, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (us != INVALID_SOCKET) {
            DWORD bytes = 0;
            GUID g_send = WSAID_WSASENDMSG;
            LPFN_WSASENDMSG sfn = nullptr;
            if (real_wsaioctl(us, SIO_GET_EXTENSION_FUNCTION_POINTER, &g_send, sizeof(g_send),
                              &sfn, sizeof(sfn), &bytes, nullptr, nullptr) == 0) {
                hook_extension_body(sfn, real_wsasendmsg_x, &hook_wsasendmsg_ext,
                                    g_wsasendmsg_hooked,
                                    static_cast<LPFN_WSASENDMSG>(orig_wsasendmsg));
            }
            GUID g_recv = WSAID_WSARECVMSG;
            LPFN_WSARECVMSG rfn = nullptr;
            if (real_wsaioctl(us, SIO_GET_EXTENSION_FUNCTION_POINTER, &g_recv, sizeof(g_recv),
                              &rfn, sizeof(rfn), &bytes, nullptr, nullptr) == 0) {
                hook_extension_body(rfn, real_wsarecvmsg_x, &hook_wsarecvmsg_ext,
                                    g_wsarecvmsg_hooked);
            }
            real_closesocket(us);
        }
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
    forget_pending_recv_for_socket(s);
    uint16_t udp_port = 0;
    uint16_t udp_family = 0;
    if (forget_udp_socket(s, udp_port, udp_family) && udp_port != 0) {
        // Notify before real_closesocket releases the local port so a new
        // socket reusing udp_port cannot race with our close notification.
        request req{};
        req.type = static_cast<uint32_t>(msg_type::udp_close);
        req.family = udp_family;
        req.src_port = udp_port;
        reply rep{};
        ask_host(req, rep);
    }
    return real_closesocket(s);
}

// --- Children ----------------------------------------------------------------

// The child is suspended and has not run: add the matching-arch DLL to its
// imports when the host says it is proxied and it can actually load it.
void carry_into_child(const PROCESS_INFORMATION& pi) {
    if (!g_dll_ansi[0]) return;
    if (process_is_restricted(pi.hProcess) || process_requires_signed_images(pi.hProcess)) return;

    const bool child_wow64 = process_is_wow64(pi.hProcess);
#ifdef _WIN64
    const bool same_arch = !child_wow64;
#else
    const bool same_arch = child_wow64;
#endif

    request req{};
    req.type = static_cast<uint32_t>(msg_type::child);
    req.child_pid = pi.dwProcessId;
    reply rep{};
    if (!ask_host(req, rep) || static_cast<verdict>(rep.verdict) != verdict::proxy) return;

    bool injected = false;
    if (same_arch) {
        LPCSTR dlls[1] = {g_dll_ansi};
        injected = DetourUpdateProcessWithDll(pi.hProcess, dlls, 1) != FALSE;
    } else if (g_sibling_dll_exists) {
        // Cross-arch child (x64 -> WOW64 or WOW64 -> x64): Detours rejects
        // cross-bitness import-table edits in-process, so hand off to the
        // matching-bitness rundll32.exe helper (calling DetourFinishHelperProcess
        // at ordinal #1 of the sibling 32/64-bit DLL). t_in_create is already
        // true here so CreateProcessW inside the helper does not recurse.
        injected = DetourProcessViaHelperW(pi.dwProcessId, g_dll_ansi, &CreateProcessW) != FALSE;
    }
    if (!injected) {
        req.type = static_cast<uint32_t>(msg_type::child_failed);
        ask_host(req, rep);
    }
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

void wide_path_to_ansi(const wchar_t* wide, char* dst, int dst_cap) {
    dst[0] = '\0';
    BOOL lossy = FALSE;
    if (WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide, -1, dst, dst_cap,
                            nullptr, &lossy) && !lossy) return;
    // A path the ANSI code page cannot spell: its 8.3 form usually can.
    wchar_t shortp[MAX_PATH] = {};
    dst[0] = '\0';
    if (GetShortPathNameW(wide, shortp, MAX_PATH) &&
        (!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, shortp, -1, dst,
                              dst_cap, nullptr, &lossy) || lossy))
        dst[0] = '\0';
}

void remember_own_path(HMODULE self) {
    wchar_t wide[MAX_PATH] = {};
    if (!GetModuleFileNameW(self, wide, MAX_PATH)) return;
    wide_path_to_ansi(wide, g_dll_ansi, static_cast<int>(sizeof(g_dll_ansi)));

    // Check whether the opposite-arch sibling DLL sits next to us so
    // DetourProcessViaHelperW can perform cross-arch child injection.
#ifdef _WIN64
    const wchar_t* sibling_name = kDllName32;
#else
    const wchar_t* sibling_name = kDllName64;
#endif
    wchar_t* slash = std::wcsrchr(wide, L'\\');
    if (slash) {
        const size_t dir_len = static_cast<size_t>(slash - wide) + 1;
        const size_t name_len = std::wcslen(sibling_name);
        if (dir_len + name_len < MAX_PATH) {
            std::wmemcpy(slash + 1, sibling_name, name_len + 1);
            const DWORD attrs = GetFileAttributesW(wide);
            g_sibling_dll_exists =
                attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
        }
    }
}

void install(HMODULE self) {
    // Loaded a second time under another spelling of its path (8.3 vs long):
    // the first copy already hooks everything.
    if (const HMODULE first = GetModuleHandleW(kDllName); first && first != self) return;
    remember_own_path(self);
    g_peers        = new (std::nothrow) std::unordered_map<SOCKET, sockaddr_storage>();
    g_udp_routes   = new (std::nothrow) std::unordered_map<SOCKET, udp_socket_state>();
    g_udp_reverse  = new (std::nothrow) std::unordered_map<uint32_t, udp_reverse_entry>();
    g_pending_recv = new (std::nothrow) std::unordered_map<LPOVERLAPPED, pending_recv>();
    if (!g_peers || !g_udp_routes || !g_udp_reverse || !g_pending_recv) return;

    const HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");   // a static import of this DLL
    const HMODULE kb  = GetModuleHandleW(L"kernelbase.dll");
    if (!resolve(ws2, "connect", real_connect) || !resolve(ws2, "WSAConnect", real_wsaconnect) ||
        !resolve(ws2, "WSAIoctl", real_wsaioctl) || !resolve(ws2, "getpeername", real_getpeername) ||
        !resolve(ws2, "closesocket", real_closesocket))
        return;
    resolve(ws2, "sendto", real_sendto);
    resolve(ws2, "WSASendTo", real_wsasendto);
    resolve(ws2, "WSASendMsg", real_wsasendmsg);
    orig_wsasendmsg = real_wsasendmsg;
    resolve(ws2, "recvfrom", real_recvfrom);
    resolve(ws2, "WSARecvFrom", real_wsarecvfrom);
    resolve(ws2, "WSAGetOverlappedResult", real_wsagor);
    resolve(kb, "GetQueuedCompletionStatus", real_gqcs);
    resolve(kb, "GetQueuedCompletionStatusEx", real_gqcsex);
    resolve(kb, "CreateProcessInternalW", real_cpiw);   // optional: children

    if (DetourTransactionBegin() != NO_ERROR) return;
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&real_connect), reinterpret_cast<PVOID>(&hook_connect));
    DetourAttach(reinterpret_cast<PVOID*>(&real_wsaconnect), reinterpret_cast<PVOID>(&hook_wsaconnect));
    DetourAttach(reinterpret_cast<PVOID*>(&real_wsaioctl), reinterpret_cast<PVOID>(&hook_wsaioctl));
    DetourAttach(reinterpret_cast<PVOID*>(&real_getpeername), reinterpret_cast<PVOID>(&hook_getpeername));
    DetourAttach(reinterpret_cast<PVOID*>(&real_closesocket), reinterpret_cast<PVOID>(&hook_closesocket));
    if (real_sendto)
        DetourAttach(reinterpret_cast<PVOID*>(&real_sendto), reinterpret_cast<PVOID>(&hook_sendto));
    if (real_wsasendto)
        DetourAttach(reinterpret_cast<PVOID*>(&real_wsasendto), reinterpret_cast<PVOID>(&hook_wsasendto));
    if (real_wsasendmsg)
        DetourAttach(reinterpret_cast<PVOID*>(&real_wsasendmsg), reinterpret_cast<PVOID>(&hook_wsasendmsg));
    if (real_recvfrom)
        DetourAttach(reinterpret_cast<PVOID*>(&real_recvfrom), reinterpret_cast<PVOID>(&hook_recvfrom));
    if (real_wsarecvfrom)
        DetourAttach(reinterpret_cast<PVOID*>(&real_wsarecvfrom), reinterpret_cast<PVOID>(&hook_wsarecvfrom));
    if (real_wsagor)
        DetourAttach(reinterpret_cast<PVOID*>(&real_wsagor), reinterpret_cast<PVOID>(&hook_wsagor));
    if (real_gqcs)
        DetourAttach(reinterpret_cast<PVOID*>(&real_gqcs), reinterpret_cast<PVOID>(&hook_gqcs));
    if (real_gqcsex)
        DetourAttach(reinterpret_cast<PVOID*>(&real_gqcsex), reinterpret_cast<PVOID>(&hook_gqcsex));
    if (real_cpiw)
        DetourAttach(reinterpret_cast<PVOID*>(&real_cpiw), reinterpret_cast<PVOID>(&hook_cpiw));
    g_installed = DetourTransactionCommit() == NO_ERROR;
    if (g_installed) {
        if (const HANDLE t = CreateThread(nullptr, 0, &prehook_extensions, nullptr, 0, nullptr))
            CloseHandle(t);
    }
}

} // namespace

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
