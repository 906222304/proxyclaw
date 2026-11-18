#pragma once

// icon_service — PNG icon bytes for a running process's executable.
// Reuses icon_cache (GDI+ based, keyed by full path). Returns null when the
// exe has no extractable icon; the HTTP layer answers that with 204.

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace clew {

class icon_cache;

class icon_service {
public:
    explicit icon_service(icon_cache& cache);

    icon_service(const icon_service&)            = delete;
    icon_service& operator=(const icon_service&) = delete;

    // pid: process whose image path the server resolves (0 = unknown).
    // name: exe file name, e.g. "chrome.exe"; checked against the PID's
    // image and used to find a running process when the PID is gone.
    [[nodiscard]] std::shared_ptr<const std::vector<std::uint8_t>>
    get(std::uint32_t pid, std::string_view name);

private:
    icon_cache& cache_;
};

} // namespace clew
