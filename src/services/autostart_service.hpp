#pragma once

// autostart_service — manage the Windows Task Scheduler entry that starts
// proxyclaw.exe when the user logs on.
//
// The service is intentionally stateless and exposes only static operations.
// It uses Task Scheduler rather than the HKCU Run key because proxyclaw.exe needs
// elevation for WinDivert / SetInterfaceDnsSettings. A Run-key entry would run
// as the unelevated user and trigger UAC on every login; a scheduled task with
// /RL HIGHEST can run with the user's elevated token without prompting.
//
// The scheduled task does not set a working directory. The registered command
// line pins --config to proxyclaw.json's absolute path; proxyclaw.exe resolves the rest
// of its sibling resources (proxyclaw.log, frontend/dist, dns_state.json) against
// its own image path via core/exe_paths.hpp, so cwd is irrelevant.

#include <filesystem>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace clew {

struct autostart_state {
    bool enabled         = false;
    bool start_minimized = false;

    // Where the running proxyclaw.exe lives. Autostart can only be enabled
    // when this is true (see core/path_trust.hpp).
    bool        location_trusted = false;
    std::string location_issue;            // empty when trusted

    // The registered task (only meaningful when enabled).
    std::string task_command;              // exe path the task launches (UTF-8)
    bool        task_matches_exe = true;   // task launches this very exe
    bool        task_trusted     = true;   // task's exe dir passes the check
    std::string task_issue;                // empty when trusted
};

class autostart_service {
public:
    // Query the ProxyClawAutoStart scheduled task.
    // Returns {enabled=false} when the task is absent. If present, the task XML
    // is inspected to decide whether --minimized is part of the registered
    // command line.
    [[nodiscard]] static autostart_state query();

    // Create, replace, or delete the ProxyClawAutoStart scheduled task.
    //
    // enabled=true:
    //   Creates or replaces the task. The registered command line pins both the
    //   absolute proxyclaw.exe path and the absolute proxyclaw.json path.
    //
    // enabled=false:
    //   Deletes the task. start_minimized is ignored. Deleting an already absent
    //   task is treated as success.
    //
    // Throws api_exception{io_error} when schtasks.exe cannot be started or
    // returns an unexpected failure.
    //
    // Throws api_exception{conflict} with details.code ==
    // "unsafe_install_location" when enabling is refused because the exe's
    // directory (or a file in it, frontend/, or an ancestor) can be modified
    // by non-administrators: an elevated logon task there would hand silent
    // admin rights to any unelevated process of the user.
    static void set(bool enabled, bool start_minimized);

    // Returns the problem with `exe_dir` as an elevated-autostart location,
    // or nullopt when only Administrators/SYSTEM/TrustedInstaller can modify it.
    [[nodiscard]] static std::optional<std::string> location_issue(const std::filesystem::path& exe_dir);
};

[[nodiscard]] inline nlohmann::json to_json(const autostart_state& s) {
    return nlohmann::json{
        {"enabled",          s.enabled},
        {"start_minimized",  s.start_minimized},
        {"location_trusted", s.location_trusted},
        {"location_issue",   s.location_issue},
        {"task_command",     s.task_command},
        {"task_matches_exe", s.task_matches_exe},
        {"task_trusted",     s.task_trusted},
        {"task_issue",       s.task_issue},
    };
}

} // namespace clew
