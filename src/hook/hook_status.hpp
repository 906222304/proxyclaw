#pragma once

// Hook mode injection observability status types.
//
// Pure standard C++ header (no Windows, no Asio) so services/, projection/,
// common/, and unit tests can share it without violating H1 layering.

#include <cstdint>
#include <functional>
#include <map>
#include <utility>

namespace clew::hook {

// Per-(pid, psn) injection state in Hook mode.
enum class inject_status : uint8_t {
    pending,      // proxied process queued for sweep, not attempted yet
    injected,     // DLL loaded via CreateRemoteThread or child import-table
    wow64,        // 32-bit process skipped (when 32-bit DLL unavailable)
    restricted,   // AppContainer or below-medium integrity
    signed_only,  // Microsoft / Store binary signature mitigation
    open_failed,  // OpenProcess failed (protected / PPL / access denied / gone)
    failed,       // remote LoadLibraryW failed or timed out
};

inline const char* inject_status_name(inject_status s) noexcept {
    switch (s) {
    case inject_status::pending:     return "pending";
    case inject_status::injected:    return "injected";
    case inject_status::wow64:       return "wow64";
    case inject_status::restricted:  return "restricted";
    case inject_status::signed_only: return "signed_only";
    case inject_status::open_failed: return "open_failed";
    case inject_status::failed:      return "failed";
    }
    return "failed";
}

inline bool inject_status_is_uninjected(inject_status s) noexcept {
    return s == inject_status::wow64 || s == inject_status::restricted ||
           s == inject_status::signed_only || s == inject_status::open_failed ||
           s == inject_status::failed;
}

// Connection `route_reason` string for a proxied process that Hook mode could
// not inject (returns nullptr when injected or pending).
inline const char* hook_skip_reason_name(inject_status s) noexcept {
    switch (s) {
    case inject_status::wow64:       return "hook_skip_wow64";
    case inject_status::restricted:  return "hook_skip_restricted";
    case inject_status::signed_only: return "hook_skip_signed_only";
    case inject_status::open_failed: return "hook_skip_open_failed";
    case inject_status::failed:      return "hook_skip_failed";
    case inject_status::pending:
    case inject_status::injected:    return nullptr;
    }
    return nullptr;
}

struct status_counts {
    uint32_t injected{0};
    uint32_t wow64{0};
    uint32_t restricted{0};
    uint32_t signed_only{0};
    uint32_t open_failed{0};
    uint32_t failed{0};
};

using process_key = std::pair<uint32_t, uint64_t>;  // (pid, psn)
using status_map = std::map<process_key, inject_status>;
using status_provider = std::function<status_map()>;

} // namespace clew::hook
