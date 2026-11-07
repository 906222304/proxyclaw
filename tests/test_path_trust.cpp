// v0.13.1 security hardening:
//   * core/path_trust.hpp — the autostart install-location check, against
//     real DACLs (System32, %TEMP%, and fixtures with explicit ACLs);
//   * common/dev_hooks.hpp — env hooks are ignored/stripped unless enabled.
// Fixture ACL edits need an elevated token (the CI runner is); without one
// those cases are skipped, the read-only cases still run.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include "common/dev_hooks.hpp"
#include "core/path_trust.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
namespace pt = clew::path_trust;

static void check(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
    std::cout << "PASS " << message << '\n';
}

static std::string describe(const std::optional<pt::issue>& i) {
    if (!i) return "trusted";
    return pt::detail::narrow(i->path.native()) + ": " + i->reason;
}

static bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION e{};
    DWORD size = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &e, sizeof(e), &size) && e.TokenIsElevated;
    CloseHandle(token);
    return ok;
}

// Owner + protected DACL from SDDL (no inheritance from the parent).
static void apply_sddl(const fs::path& p, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr))
        throw std::runtime_error("bad SDDL");
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    GetSecurityDescriptorOwner(sd, &owner, &defaulted);
    const DWORD rc = SetNamedSecurityInfoW(const_cast<wchar_t*>(p.c_str()), SE_FILE_OBJECT,
                                           OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                                               PROTECTED_DACL_SECURITY_INFORMATION,
                                           owner, nullptr, dacl, nullptr);
    LocalFree(sd);
    if (rc != ERROR_SUCCESS)
        throw std::runtime_error("SetNamedSecurityInfoW failed: " + std::to_string(rc));
}

static void touch(const fs::path& p) { std::ofstream(p) << "x"; }

static bool enable_privilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid) &&
              AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

// Owner only (BUILTIN\Administrators), DACL untouched.
static void set_owner_admins(const fs::path& p) {
    BYTE  buf[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(buf);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, buf, &size))
        throw std::runtime_error("CreateWellKnownSid failed");
    const DWORD rc = SetNamedSecurityInfoW(const_cast<wchar_t*>(p.c_str()), SE_FILE_OBJECT,
                                           OWNER_SECURITY_INFORMATION, buf, nullptr, nullptr, nullptr);
    if (rc != ERROR_SUCCESS) throw std::runtime_error("set owner failed: " + std::to_string(rc));
}

static void path_trust_cases() {
    wchar_t sys[MAX_PATH]{};
    GetSystemDirectoryW(sys, MAX_PATH);
    const auto ps_dir = fs::path{sys} / L"WindowsPowerShell" / L"v1.0";
    const auto system32 = pt::check_install_dir(ps_dir);
    std::cout << "  System32\\WindowsPowerShell\\v1.0: " << describe(system32) << '\n';
    // A stock, TrustedInstaller-owned folder with a handful of files.
    check(!system32, "a stock Windows system folder is trusted");

    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    const auto temp_dir = fs::path{tmp} / L"proxyclaw-trust-user";
    fs::create_directories(temp_dir);
    const auto temp = pt::check_install_dir(temp_dir);
    std::cout << "  %TEMP% fixture: " << describe(temp) << '\n';
    check(temp.has_value(), "a folder under the user's %TEMP% is not trusted");
    fs::remove_all(temp_dir);

    if (!is_elevated()) {
        std::cout << "SKIP fixture ACL cases (not elevated)\n";
        return;
    }

    // Fixture under Program Files so its ancestors are the stock ones.
    wchar_t pf[MAX_PATH]{};
    if (!GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH)) throw std::runtime_error("no %ProgramFiles%");
    const auto base = fs::path{pf} / (L"ProxyClawTrustTest-" + std::to_wstring(GetCurrentProcessId()));
    fs::remove_all(base);
    fs::create_directories(base / L"frontend" / L"dist");
    touch(base / L"proxyclaw.exe");
    touch(base / L"WinDivert.dll");
    touch(base / L"frontend" / L"dist" / L"index.html");

    struct cleanup {
        fs::path p;
        ~cleanup() {
            std::error_code ec;
            // Restore a removable ACL first, then delete.
            try { apply_sddl(p, L"O:BAD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"); } catch (...) {}
            fs::remove_all(p, ec);
        }
    } guard{base};

    // Admin-only, inherited by everything below. Owners are pinned to
    // Administrators (the runner's default owner may be its user account).
    constexpr const wchar_t* admin_only = L"O:BAD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)";
    for (const auto& e : fs::recursive_directory_iterator(base)) set_owner_admins(e.path());
    // Protected DACL on the root; SetNamedSecurityInfo propagates the
    // inheritable ACEs to the (unprotected) children.
    apply_sddl(base, admin_only);
    {
        const auto r = pt::check_install_dir(base);
        std::cout << "  admin-only fixture: " << describe(r) << '\n';
        check(!r, "an admin-only folder under Program Files is trusted");
    }

    // BUILTIN\Users may add files to the install folder -> untrusted.
    apply_sddl(base, L"O:BAD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1201bf;;;BU)");
    {
        const auto r = pt::check_install_dir(base);
        std::cout << "  users-writable fixture: " << describe(r) << '\n';
        check(r.has_value() && r->path.filename() == base.filename(), "Users write on the folder is rejected");
    }
    apply_sddl(base, admin_only);

    // One planted-DLL candidate with an explicit Users:Modify ACE.
    apply_sddl(base / L"WinDivert.dll", L"O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1301bf;;;BU)");
    {
        const auto r = pt::check_install_dir(base);
        std::cout << "  writable DLL fixture: " << describe(r) << '\n';
        check(r.has_value() && r->path.filename() == L"WinDivert.dll", "a user-writable sibling DLL is rejected");
    }
    apply_sddl(base / L"WinDivert.dll", L"O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)");

    // A writable UI file deep in frontend/dist.
    apply_sddl(base / L"frontend" / L"dist" / L"index.html", L"O:BAD:(A;;FA;;;BA)(A;;FA;;;WD)");
    {
        const auto r = pt::check_install_dir(base);
        std::cout << "  writable frontend fixture: " << describe(r) << '\n';
        check(r.has_value() && r->path.filename() == L"index.html", "a world-writable frontend file is rejected");
    }
    apply_sddl(base / L"frontend" / L"dist" / L"index.html", L"O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)");

    // Owned by a non-admin principal (here: Users) -> untrusted even with a
    // tight DACL. Assigning a foreign owner needs SeRestorePrivilege.
    if (enable_privilege(L"SeRestorePrivilege")) {
        apply_sddl(base / L"proxyclaw.exe", L"O:BUD:(A;;FA;;;BA)(A;;FA;;;SY)");
        {
            const auto r = pt::check_install_dir(base);
            std::cout << "  foreign-owner fixture: " << describe(r) << '\n';
            check(r.has_value() && r->path.filename() == L"proxyclaw.exe", "a file owned by a non-admin is rejected");
        }
        apply_sddl(base / L"proxyclaw.exe", L"O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)");
    } else {
        std::cout << "SKIP foreign-owner case (SeRestorePrivilege unavailable)\n";
    }
    check(!pt::check_install_dir(base), "restoring the ACLs makes the folder trusted again");
}

static void dev_hook_cases() {
    _putenv_s("PROXYCLAW_DEV_URL", "http://evil.example");
    _putenv_s("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--remote-debugging-port=9222");
    _putenv_s("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", "C:\\evil");
#ifdef NDEBUG
    check(!clew::dev_hooks_enabled(), "release build: dev hooks are off by default");
    check(clew::dev_env("PROXYCLAW_DEV_URL") == nullptr, "release build: PROXYCLAW_DEV_URL is ignored");
    const auto removed = clew::strip_untrusted_environment();
    check(removed.size() == 3, "untrusted variables are reported as removed");
    check(std::getenv("PROXYCLAW_DEV_URL") == nullptr &&
              GetEnvironmentVariableA("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", nullptr, 0) == 0 &&
              GetEnvironmentVariableA("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", nullptr, 0) == 0,
          "untrusted variables are gone from both the CRT and the Win32 environment");
#endif
    _putenv_s("PROXYCLAW_DEV_URL", "http://localhost:5173");
    clew::enable_dev_hooks();
    check(clew::dev_hooks_enabled(), "--dev-hooks enables the hooks");
    check(clew::dev_env("PROXYCLAW_DEV_URL") != nullptr &&
              std::string(clew::dev_env("PROXYCLAW_DEV_URL")) == "http://localhost:5173",
          "with dev hooks the env value is returned");
    check(clew::strip_untrusted_environment().empty() && std::getenv("PROXYCLAW_DEV_URL") != nullptr,
          "with dev hooks the environment is left alone");
    _putenv_s("PROXYCLAW_DEV_URL", "");
}

int main() {
    try {
        path_trust_cases();
        dev_hook_cases();
        std::cout << "path trust / dev hooks: all passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
