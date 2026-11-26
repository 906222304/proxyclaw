#pragma once

// Minimal, pure PE32 (x86) export table lookup over an abstract memory reader.
//
// Used by hook_injector.hpp to resolve LoadLibraryW inside a 32-bit (WOW64)
// target's mapped SysWOW64\kernel32.dll via ReadProcessMemory without touching
// disk or injecting shellcode. Free of Windows headers so unit tests can
// exercise it on any platform.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace clew::hook::pe32 {

inline uint16_t rd16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

inline uint32_t rd32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// Read a NUL-terminated ASCII export name at `rva` (capped at `max_len`).
// Falls back to byte-by-byte reads if a chunk read crosses a page boundary.
template <typename ReadFn>
inline std::optional<std::string> read_cstr(ReadFn&& read_at, uint32_t rva,
                                            std::size_t max_len = 128) {
    std::array<char, 128> buf{};
    const std::size_t cap = std::min(max_len, buf.size());
    if (read_at(rva, buf.data(), cap)) {
        const void* nul = std::memchr(buf.data(), '\0', cap);
        if (!nul) return std::nullopt;
        const auto len = static_cast<std::size_t>(static_cast<const char*>(nul) - buf.data());
        return std::string(buf.data(), len);
    }
    std::string out;
    out.reserve(32);
    for (std::size_t i = 0; i < cap; ++i) {
        char ch = 0;
        if (!read_at(rva + static_cast<uint32_t>(i), &ch, 1)) return std::nullopt;
        if (ch == '\0') return out;
        out.push_back(ch);
    }
    return std::nullopt;
}

// Locate a non-forwarded exported symbol's RVA inside a memory-mapped PE32
// image. `read_at(uint32_t rva, void* dst, std::size_t len) -> bool` reads
// `len` bytes from `module_base + rva`.
template <typename ReadFn>
inline std::optional<uint32_t> find_export_rva(ReadFn&& read_at, std::string_view symbol) {
    if (symbol.empty() || symbol.size() >= 128) return std::nullopt;

    std::array<uint8_t, 64> dos{};
    if (!read_at(0, dos.data(), dos.size())) return std::nullopt;
    if (dos[0] != 'M' || dos[1] != 'Z') return std::nullopt;
    const uint32_t e_lfanew = rd32(dos.data() + 0x3C);
    if (e_lfanew < 64 || e_lfanew > 0x100000u) return std::nullopt;

    // NT signature (4) + IMAGE_FILE_HEADER (20) + IMAGE_OPTIONAL_HEADER32 up to DataDirectory[0] (104)
    std::array<uint8_t, 128> nt{};
    if (!read_at(e_lfanew, nt.data(), nt.size())) return std::nullopt;
    if (rd32(nt.data()) != 0x00004550u) return std::nullopt;               // "PE\0\0"
    if (rd16(nt.data() + 4) != 0x014Cu) return std::nullopt;               // IMAGE_FILE_MACHINE_I386
    if (rd16(nt.data() + 20) < 104u) return std::nullopt;                  // SizeOfOptionalHeader
    if (rd16(nt.data() + 24) != 0x010Bu) return std::nullopt;              // IMAGE_NT_OPTIONAL_HDR32_MAGIC
    if (rd32(nt.data() + 24 + 92) < 1u) return std::nullopt;               // NumberOfRvaAndSizes

    const uint32_t export_rva  = rd32(nt.data() + 24 + 96);
    const uint32_t export_size = rd32(nt.data() + 24 + 100);
    if (export_rva == 0 || export_size < 40u) return std::nullopt;

    std::array<uint8_t, 40> exp{};
    if (!read_at(export_rva, exp.data(), exp.size())) return std::nullopt;
    const uint32_t num_funcs = rd32(exp.data() + 20);
    const uint32_t num_names = rd32(exp.data() + 24);
    const uint32_t funcs_rva = rd32(exp.data() + 28);
    const uint32_t names_rva = rd32(exp.data() + 32);
    const uint32_t ords_rva  = rd32(exp.data() + 36);
    if (num_names == 0 || num_names > 65536u || num_funcs == 0 || num_funcs > 65536u) {
        return std::nullopt;
    }

    auto resolve_index = [&](uint32_t idx) -> std::optional<uint32_t> {
        std::array<uint8_t, 2> ord_buf{};
        if (!read_at(ords_rva + idx * 2u, ord_buf.data(), 2)) return std::nullopt;
        const uint16_t ord = rd16(ord_buf.data());
        if (ord >= num_funcs) return std::nullopt;

        std::array<uint8_t, 4> fn_buf{};
        if (!read_at(funcs_rva + static_cast<uint32_t>(ord) * 4u, fn_buf.data(), 4)) {
            return std::nullopt;
        }
        const uint32_t fn_rva = rd32(fn_buf.data());
        if (fn_rva == 0) return std::nullopt;
        // Reject forwarded exports (RVA pointing inside the export directory).
        if (fn_rva >= export_rva && fn_rva < export_rva + export_size) return std::nullopt;
        return fn_rva;
    };

    // Binary search (PE/COFF requires export name pointer table sorted ascending).
    uint32_t lo = 0, hi = num_names;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2u;
        std::array<uint8_t, 4> nr_buf{};
        if (!read_at(names_rva + mid * 4u, nr_buf.data(), 4)) return std::nullopt;
        const auto name = read_cstr(read_at, rd32(nr_buf.data()));
        if (!name) return std::nullopt;
        const int cmp = std::string_view(*name).compare(symbol);
        if (cmp == 0) return resolve_index(mid);
        if (cmp < 0) lo = mid + 1u;
        else hi = mid;
    }
    return std::nullopt;
}

} // namespace clew::hook::pe32
