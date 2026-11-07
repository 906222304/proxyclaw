#pragma once

// path_trust — can a non-administrator modify what an elevated launch runs?
//
// The ProxyClawAutoStart task starts proxyclaw.exe elevated (/RL HIGHEST) at
// every logon without a UAC prompt. If any unelevated process of the user can
// replace proxyclaw.exe, drop a DLL next to it, or edit frontend/dist (served
// into the elevated UI with the session cookie), that process gets silent
// administrator rights. So autostart is only allowed when the install location
// is writable exclusively by Administrators / SYSTEM / TrustedInstaller —
// e.g. a folder under C:\Program Files.
//
// The check reads owners and DACLs (no AccessCheck against a synthetic token):
//   * the install directory itself, every regular file directly inside it,
//     and frontend/ recursively: no allow-ACE that grants write/delete/
//     re-ACL rights to any SID outside the trusted set, owner trusted;
//   * every ancestor directory up to the root: nobody untrusted may delete /
//     rename children (FILE_DELETE_CHILD), delete/rename the directory itself,
//     or change its DACL/owner — any of which would allow swapping the whole
//     folder. Plain "create subfolder" (C:\ grants that to Authenticated Users)
//     is fine.
// Inherit-only ACEs do not apply to the object and are skipped. Deny ACEs are
// ignored (the check is conservative: a grant counts even if a deny might
// cancel it). Object/compound ACE types with write bits count as untrusted.
// An unreadable descriptor, a NULL DACL, or a network path is untrusted.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <cstddef>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <system_error>

namespace clew::path_trust {

struct issue {
    std::filesystem::path path;    // object that failed the check
    std::string           reason;  // English, for logs / API error text
};

// Rights that let the holder change the object's content, replace or rename
// it, or grant itself those rights.
inline constexpr ACCESS_MASK object_write_rights =
    FILE_WRITE_DATA |        // = FILE_ADD_FILE on directories
    FILE_APPEND_DATA |       // = FILE_ADD_SUBDIRECTORY on directories
    FILE_DELETE_CHILD |
    DELETE | WRITE_DAC | WRITE_OWNER |
    GENERIC_WRITE | GENERIC_ALL;

// Rights on an ancestor directory that let the holder swap a child folder.
inline constexpr ACCESS_MASK ancestor_write_rights =
    FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

namespace detail {

inline std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(n > 0 ? n : 0), '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n,
                            nullptr, nullptr);
    return out;
}

inline std::string sid_name(PSID sid) {
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD   name_len = 256, domain_len = 256;
    SID_NAME_USE use{};
    if (LookupAccountSidW(nullptr, sid, name, &name_len, domain, &domain_len, &use)) {
        std::wstring full = domain_len ? std::wstring(domain) + L"\\" + name : std::wstring(name);
        return narrow(full);
    }
    LPWSTR str = nullptr;
    if (ConvertSidToStringSidW(sid, &str)) {
        std::string s = narrow(str);
        LocalFree(str);
        return s;
    }
    return "<unknown SID>";
}

inline bool is_trusted_installer(PSID sid) {
    // NT SERVICE\TrustedInstaller (service SID, identical on every machine).
    static const PSID ti = [] {
        PSID p = nullptr;
        ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &p);
        return p;  // intentionally never freed (process lifetime)
    }();
    return ti && EqualSid(sid, ti);
}

} // namespace detail

// Administrators, LocalSystem and TrustedInstaller: a process acting as any of
// these is already elevated, so their write access is not an escalation path.
[[nodiscard]] inline bool is_trusted_sid(PSID sid) {
    if (!sid || !IsValidSid(sid)) return false;
    return IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
           IsWellKnownSid(sid, WinLocalSystemSid) ||
           detail::is_trusted_installer(sid);
}

// Checks one object's owner and DACL against `rights`.
[[nodiscard]] inline std::optional<issue> check_object(const std::filesystem::path& p,
                                                       ACCESS_MASK rights) {
    PSID                 owner = nullptr;
    PACL                 dacl  = nullptr;
    PSECURITY_DESCRIPTOR sd    = nullptr;
    const DWORD rc = GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT,
                                           OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                           &owner, nullptr, &dacl, nullptr, &sd);
    if (rc != ERROR_SUCCESS) {
        return issue{p, std::format("cannot read its security descriptor (Win32 error {})", rc)};
    }
    struct sd_free { PSECURITY_DESCRIPTOR s; ~sd_free() { if (s) LocalFree(s); } } guard{sd};

    // The owner can always rewrite the DACL.
    if (!is_trusted_sid(owner)) {
        return issue{p, std::format("its owner {} is not Administrators/SYSTEM/TrustedInstaller",
                                    detail::sid_name(owner))};
    }
    if (!dacl) {
        return issue{p, "it has no DACL (everyone has full access)"};
    }

    ACL_SIZE_INFORMATION info{};
    if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) {
        return issue{p, std::format("cannot read its DACL (Win32 error {})", GetLastError())};
    }
    for (DWORD i = 0; i < info.AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw) || !raw) continue;
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;  // applies to children only

        switch (header->AceType) {
            case ACCESS_ALLOWED_ACE_TYPE:
            case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
                // Same layout for both: Header, Mask, SidStart.
                const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
                if ((ace->Mask & rights) == 0) break;
                auto* sid = const_cast<DWORD*>(&ace->SidStart);
                if (is_trusted_sid(sid)) break;
                return issue{p, std::format("{} has write access (mask {:#x})",
                                            detail::sid_name(sid),
                                            static_cast<unsigned>(ace->Mask))};
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
            case ACCESS_ALLOWED_COMPOUND_ACE_TYPE: {
                const auto* ace = static_cast<const ACCESS_ALLOWED_OBJECT_ACE*>(raw);
                if (ace->Mask & rights)
                    return issue{p, "an object-type ACE grants write access"};
                break;
            }
            default:
                break;  // deny / audit / label ACEs
        }
    }
    return std::nullopt;
}

// Full check of an install directory (see header comment). `dir` should be
// the directory containing proxyclaw.exe.
[[nodiscard]] inline std::optional<issue> check_install_dir(const std::filesystem::path& dir_in) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path dir = fs::canonical(dir_in, ec);  // resolves junctions / symlinks
    if (ec) return issue{dir_in, std::format("cannot resolve the path ({})", ec.message())};

    const std::wstring& native = dir.native();
    if (native.starts_with(L"\\\\")) {
        return issue{dir, "it is on a network location"};
    }

    if (auto bad = check_object(dir, object_write_rights)) return bad;

    // Ancestors up to (and including) the drive root.
    for (fs::path a = dir.parent_path(); !a.empty(); a = a.parent_path()) {
        if (auto bad = check_object(a, ancestor_write_rights)) return bad;
        if (a == a.parent_path()) break;
    }

    // Everything directly in the directory: exe, DLLs, driver, config, ...
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        if (auto bad = check_object(it->path(), object_write_rights)) return bad;
    }
    if (ec) return issue{dir, std::format("cannot list the directory ({})", ec.message())};

    // The UI that is served into the elevated WebView.
    const fs::path frontend = dir / L"frontend";
    if (fs::exists(frontend, ec)) {
        if (auto bad = check_object(frontend, object_write_rights)) return bad;
        std::size_t budget = 5000;  // a dist folder has a few dozen entries
        for (fs::recursive_directory_iterator it(frontend, fs::directory_options::none, ec), end;
             !ec && it != end; it.increment(ec)) {
            if (--budget == 0) return issue{frontend, "too many files to verify"};
            if (auto bad = check_object(it->path(), object_write_rights)) return bad;
        }
        if (ec) return issue{frontend, std::format("cannot list the directory ({})", ec.message())};
    }
    return std::nullopt;
}

} // namespace clew::path_trust
