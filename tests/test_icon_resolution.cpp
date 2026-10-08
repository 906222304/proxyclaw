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
    const auto& png = cache.get_icon("assets/proxyclaw.ico");
    if (png.size() < 24 || png[0] != 0x89 || png[1] != 'P' || png[2] != 'N' ||
        png[3] != 'G' || read_u32(png, 16) != 64 || read_u32(png, 20) != 64) {
        std::cerr << "Shell icon must encode a 64x64 PNG\n";
        return 2;
    }
    if (&png != &cache.get_icon("assets/proxyclaw.ico")) return 3;
    std::cout << "PASS: high-resolution Shell icon extraction, 64x64 PNG and cache reuse\n";
}
