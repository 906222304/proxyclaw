#pragma once

// Hook mode: load proxyclaw_hook64.dll (or proxyclaw_hook32.dll for WOW64
// processes) into a running process via CreateRemoteThread + LoadLibraryW.
// New children of an injected process are handled inside the DLL instead,
// before their first instruction runs.
//
// Processes that cannot take the DLL are skipped rather than attempted:
//   - 32-bit (WOW64) processes when proxyclaw_hook32.dll is unavailable;
//   - AppContainer or below-medium integrity: they could not open the
//     control pipe's DLL file or would be killed by their own sandbox;
//   - Microsoft/Store-signed-only mitigation: the loader would refuse it.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#ifdef _WIN64
#include <psapi.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>

#ifdef _WIN64
#include "hook/pe32_export.hpp"
#endif

namespace clew::hook {

enum class inject_result {
    ok,
    open_failed,     // gone, protected, or access denied
    wow64,           // 32-bit process (when proxyclaw_hook32.dll unavailable)
    restricted,      // AppContainer / low integrity
    signed_only,     // binary signature mitigation
    failed,          // remote LoadLibraryW failed or timed out
};

inline const char* inject_result_name(inject_result r) {
    switch (r) {
    case inject_result::ok:          return "ok";
    case inject_result::open_failed: return "open_failed";
    case inject_result::wow64:       return "wow64";
    case inject_result::restricted:  return "restricted";
    case inject_result::signed_only: return "signed_only";
    case inject_result::failed:      return "failed";
    }
    return "?";
}

// SeDebugPrivilege lets an elevated ProxyClaw open other users' and service
// processes. Best effort.
inline void enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
}

// AppContainer or integrity below medium.
inline bool process_is_restricted(HANDLE process) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return false;
    bool restricted = false;
    DWORD is_app_container = 0, len = 0;
    if (GetTokenInformation(token, TokenIsAppContainer, &is_app_container, sizeof(is_app_container), &len) &&
        is_app_container) restricted = true;
    alignas(8) unsigned char buf[64]{};
    if (!restricted && GetTokenInformation(token, TokenIntegrityLevel, buf, sizeof(buf), &len)) {
        const auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf);
        const DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
        const DWORD level = count ? *GetSidSubAuthority(label->Label.Sid, count - 1) : 0;
        if (level < SECURITY_MANDATORY_MEDIUM_RID) restricted = true;
    }
    CloseHandle(token);
    return restricted;
}

inline bool process_requires_signed_images(HANDLE process) {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
    if (!GetProcessMitigationPolicy(process, ProcessSignaturePolicy, &sig, sizeof(sig))) return false;
    return sig.MicrosoftSignedOnly || sig.StoreSignedOnly;
}

inline bool process_is_wow64(HANDLE process) {
    USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN, native = 0;
    if (IsWow64Process2(process, &machine, &native)) return machine != IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL wow = FALSE;
    return IsWow64Process(process, &wow) && wow;
}

#ifdef _WIN64

// Resolve 32-bit SysWOW64\kernel32.dll!LoadLibraryW inside a WOW64 target via
// K32EnumProcessModulesEx(LIST_MODULES_32BIT) + ReadProcessMemory PE32 export
// lookup. Zero shellcode, zero disk reads.
inline LPTHREAD_START_ROUTINE find_wow64_loadlibraryw(HANDLE process) {
    std::vector<HMODULE> mods(256);
    for (int attempt = 0; attempt < 4; ++attempt) {
        DWORD needed = 0;
        if (!K32EnumProcessModulesEx(process, mods.data(),
                                     static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                     &needed, LIST_MODULES_32BIT)) {
            Sleep(50);
            continue;
        }
        const std::size_t count = needed / sizeof(HMODULE);
        if (count > mods.size()) {
            mods.resize(count);
            if (!K32EnumProcessModulesEx(process, mods.data(),
                                         static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                         &needed, LIST_MODULES_32BIT)) {
                Sleep(50);
                continue;
            }
        }
        const std::size_t actual = std::min(mods.size(), static_cast<std::size_t>(needed / sizeof(HMODULE)));
        for (std::size_t i = 0; i < actual; ++i) {
            wchar_t base_name[MAX_PATH] = {};
            if (!K32GetModuleBaseNameW(process, mods[i], base_name, ARRAYSIZE(base_name))) continue;
            if (_wcsicmp(base_name, L"kernel32.dll") != 0) continue;

            const auto base = reinterpret_cast<std::uintptr_t>(mods[i]);
            if (base == 0 || base > 0xFFFFFFFFULL) continue;
            auto read_at = [process, base](uint32_t rva, void* dst, std::size_t len) -> bool {
                SIZE_T got = 0;
                return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + rva),
                                         dst, len, &got) != FALSE && got == len;
            };
            if (const auto rva = pe32::find_export_rva(read_at, "LoadLibraryW")) {
                return reinterpret_cast<LPTHREAD_START_ROUTINE>(base + *rva);
            }
            return nullptr;
        }
        // Newly spawned WOW64 process may not have mapped SysWOW64\kernel32.dll yet.
        Sleep(50);
    }
    return nullptr;
}

inline inject_result inject_into(DWORD pid, const std::wstring& dll64_path,
                                 const std::wstring& dll32_path = {}) {
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                 PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                 FALSE, pid);
    if (!process) return inject_result::open_failed;
    inject_result result = inject_result::failed;
    do {
        if (process_is_restricted(process))        { result = inject_result::restricted; break; }
        if (process_requires_signed_images(process)) { result = inject_result::signed_only; break; }

        const bool is_wow64 = process_is_wow64(process);
        if (is_wow64 && dll32_path.empty())        { result = inject_result::wow64; break; }

        const std::wstring& dll_path = is_wow64 ? dll32_path : dll64_path;
        LPTHREAD_START_ROUTINE load = nullptr;
        if (is_wow64) {
            load = find_wow64_loadlibraryw(process);
        } else {
            // kernel32 sits at the same address in every x64 process of this boot.
            load = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        }
        if (!load) break;

        const SIZE_T bytes = (dll_path.size() + 1) * sizeof(wchar_t);
        void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) break;
        if (is_wow64 && reinterpret_cast<std::uintptr_t>(remote) > 0xFFFFFFFFULL) {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            break;
        }
        if (WriteProcessMemory(process, remote, dll_path.c_str(), bytes, nullptr)) {
            HANDLE thread = CreateRemoteThread(process, nullptr, 0, load, remote, 0, nullptr);
            if (thread) {
                if (WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0) {
                    DWORD code = 0;
                    // The low 32 bits of the HMODULE: non-zero means it loaded.
                    if (GetExitCodeThread(thread, &code) && code != 0) result = inject_result::ok;
                    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
                }
                // On timeout the remote buffer is left alone: the loader may
                // still be reading it.
                CloseHandle(thread);
            } else {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
        } else {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
    } while (false);
    CloseHandle(process);
    return result;
}

#endif // _WIN64

} // namespace clew::hook
