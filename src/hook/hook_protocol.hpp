#pragma once

// Wire format between proxyclaw.exe and the injected proxyclaw_hook64.dll
// (interception.mode = "hook"). One request, one reply, one message-mode
// named-pipe transaction (CallNamedPipeW on the DLL side), so a dead or
// restarted host costs the application one failed open and nothing else.
//
// The host never trusts the PID in a request: the CONNECT owner is the
// pipe client (GetNamedPipeClientProcessId). `child_pid` is only a question
// ("should this new process get the DLL?"), answered from the rules.
//
// Shared by both binaries: keep it free of C++ library and Windows headers
// beyond <cstdint>, and bump kVersion on any layout change.

#include <cstdint>

namespace clew::hook {

inline constexpr uint32_t kMagic   = 0x4B4F4850u;   // "PHOK"
inline constexpr uint32_t kVersion = 1;
inline constexpr wchar_t  kPipeName[] = L"\\\\.\\pipe\\proxyclaw-hook-v1";
// Next to proxyclaw.exe: 64-bit DLL for x64 processes, 32-bit DLL for WOW64.
inline constexpr wchar_t  kDllName64[] = L"proxyclaw_hook64.dll";
inline constexpr wchar_t  kDllName32[] = L"proxyclaw_hook32.dll";
#ifdef _WIN64
inline constexpr wchar_t  kDllName[]   = L"proxyclaw_hook64.dll";
#else
inline constexpr wchar_t  kDllName[]   = L"proxyclaw_hook32.dll";
#endif

enum class msg_type : uint32_t {
    connect      = 1,   // a TCP connect() / WSAConnect / ConnectEx is about to run
    child        = 2,   // a suspended child was just created: inject it?
    child_failed = 3,   // import-table edit failed: let the sweep retry after resume
};

enum class verdict : uint32_t {
    direct = 0,    // call the real connect unchanged
    proxy  = 1,    // connect to the loopback relay port instead
    block  = 2,    // fail the connect with reply.error (IPv6 -> IPv4 fallback)
};

struct request {
    uint32_t magic;
    uint32_t version;
    uint32_t type;        // msg_type
    uint32_t child_pid;   // msg_type::child only
    uint16_t family;      // 4 or 6 (an IPv4-mapped IPv6 destination is sent as 4)
    uint16_t dst_port;    // host byte order
    uint16_t src_port;    // host byte order: the socket's bound local port
    uint16_t reserved;
    uint8_t  dst[16];     // network byte order; IPv4 in dst[0..3]
};

struct reply {
    uint32_t magic;
    uint32_t verdict;     // verdict
    uint16_t relay_port;  // verdict::proxy: 127.0.0.1 (family 4) or [::1] (family 6)
    uint16_t reserved;
    uint32_t error;       // verdict::block: the WSA error to report
};

static_assert(sizeof(request) == 40, "hook request layout changed: bump kVersion");
static_assert(sizeof(reply) == 16, "hook reply layout changed: bump kVersion");

} // namespace clew::hook
