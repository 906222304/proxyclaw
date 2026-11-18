// Exercise actual Shell extraction + GDI+ encoding with the project's icon.
#include "api/icon_cache.hpp"
#include <iostream>
#include <stdexcept>

static unsigned read_u32(const std::vector<uint8_t>& png, size_t offset) {
    return (unsigned(png[offset]) << 24) | (unsigned(png[offset + 1]) << 16) |
           (unsigned(png[offset + 2]) << 8) | unsigned(png[offset + 3]);
}

int main() {
    clew::icon_cache cache;
    if (!cache.init()) return 1;
    clew::scoped_exit guard{[&] { cache.shutdown(); }};
    const auto ptr = cache.get_icon("assets/proxyclaw.ico");
    if (!ptr) { std::cerr << "no icon extracted\n"; return 2; }
    const auto& png = *ptr;
    if (png.size() < 24 || png[0] != 0x89 || png[1] != 'P' || png[2] != 'N' ||
        png[3] != 'G' || read_u32(png, 16) != 64 || read_u32(png, 20) != 64) {
        std::cerr << "Shell icon must encode a 64x64 PNG\n";
        return 2;
    }
    if (ptr != cache.get_icon("assets/proxyclaw.ico")) return 3;
    // A path without an icon is remembered (negative entry) instead of
    // being re-extracted on every request.
    if (cache.get_icon("assets/does-not-exist.exe")) return 4;
    if (cache.get_icon("assets/does-not-exist.exe")) return 5;
    // The current process resolves by PID; a wrong name falls back to a
    // name lookup that finds nothing.
    if (clew::icon_cache::process_image_path(GetCurrentProcessId()).empty()) return 6;
    if (cache.get_icon_for_process(GetCurrentProcessId(), "no-such-process-name.exe")) return 7;
    std::cout << "PASS: high-resolution Shell icon extraction, 64x64 PNG and cache reuse, negative cache, PID resolution\n";
}
