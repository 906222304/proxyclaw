#pragma once

// icon_service — extract 16x16 PNG icon bytes for a given exe.
// Reuses the legacy icon_cache (GDI+ based). Returns an empty vector when the
// exe has no extractable icon — the HTTP layer answers that with 204.

#include <cstdint>
#include <string_view>
#include <vector>

namespace clew {

class icon_cache;

class icon_service {
public:
    explicit icon_service(icon_cache& cache);

    icon_service(const icon_service&)            = delete;
    icon_service& operator=(const icon_service&) = delete;

    // name: executable file name, e.g. "chrome.exe"; path may be empty.
    // Returns a copy of the PNG bytes, or an empty vector for "no icon".
    [[nodiscard]] std::vector<std::uint8_t> get(std::string_view name,
                                                std::string_view path);

private:
    icon_cache& cache_;
};

} // namespace clew
