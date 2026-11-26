#pragma once

// Minimal PKZIP archive writer (Store method 0 + IEEE 802.3 CRC-32) with zero
// external dependencies (v0.18 #4 diagnostics export). Pure C++23 so it can be
// compiled and validated cross-platform.

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

namespace clew {

inline uint32_t crc32_ieee(const uint8_t* data, std::size_t len) noexcept {
    static constexpr auto kTable = []() {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int b = 0; b < 8; ++b) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();
    uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc = kTable[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

inline uint32_t crc32_ieee(std::string_view s) noexcept {
    return crc32_ieee(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

class mini_zip_writer {
public:
    explicit mini_zip_writer(std::time_t timestamp_utc = std::time(nullptr)) {
        encode_dos_datetime(timestamp_utc, dos_time_, dos_date_);
    }

    void add_file(std::string_view name, std::string_view content) {
        if (name.size() > 0xFFFFu || content.size() > 0xFFFFFFFFu) return;
        entry e;
        e.name.assign(name);
        e.data.assign(content);
        e.crc32 = crc32_ieee(content);
        entries_.push_back(std::move(e));
    }

    [[nodiscard]] std::string finish() const {
        std::size_t approx = 64;
        for (const auto& e : entries_) {
            approx += 30 + e.name.size() + e.data.size() + 46 + e.name.size();
        }
        std::string out;
        out.reserve(approx);

        std::vector<uint32_t> local_offsets;
        local_offsets.reserve(entries_.size());

        // 1. Local file headers + uncompressed data (method 0 = STORE).
        for (const auto& e : entries_) {
            local_offsets.push_back(static_cast<uint32_t>(out.size()));
            const uint32_t size32 = static_cast<uint32_t>(e.data.size());
            const uint16_t name_len = static_cast<uint16_t>(e.name.size());

            put_u32(out, 0x04034B50u);  // local file header signature
            put_u16(out, 20u);          // version needed to extract (2.0)
            put_u16(out, 0x0800u);      // UTF-8 filename flag
            put_u16(out, 0u);           // compression method: STORE
            put_u16(out, dos_time_);
            put_u16(out, dos_date_);
            put_u32(out, e.crc32);
            put_u32(out, size32);       // compressed size
            put_u32(out, size32);       // uncompressed size
            put_u16(out, name_len);
            put_u16(out, 0u);           // extra field length
            out.append(e.name);
            out.append(e.data);
        }

        // 2. Central directory headers.
        const uint32_t cd_offset = static_cast<uint32_t>(out.size());
        for (std::size_t i = 0; i < entries_.size(); ++i) {
            const auto& e = entries_[i];
            const uint32_t size32 = static_cast<uint32_t>(e.data.size());
            const uint16_t name_len = static_cast<uint16_t>(e.name.size());

            put_u32(out, 0x02014B50u);  // central file header signature
            put_u16(out, 20u);          // version made by
            put_u16(out, 20u);          // version needed to extract
            put_u16(out, 0x0800u);      // UTF-8 filename flag
            put_u16(out, 0u);           // compression method: STORE
            put_u16(out, dos_time_);
            put_u16(out, dos_date_);
            put_u32(out, e.crc32);
            put_u32(out, size32);       // compressed size
            put_u32(out, size32);       // uncompressed size
            put_u16(out, name_len);
            put_u16(out, 0u);           // extra field length
            put_u16(out, 0u);           // file comment length
            put_u16(out, 0u);           // disk number start
            put_u16(out, 0u);           // internal file attributes
            put_u32(out, 0u);           // external file attributes
            put_u32(out, local_offsets[i]);
            out.append(e.name);
        }
        const uint32_t cd_size = static_cast<uint32_t>(out.size()) - cd_offset;

        // 3. End of central directory record.
        const uint16_t count16 = static_cast<uint16_t>(entries_.size());
        put_u32(out, 0x06054B50u);      // EOCD signature
        put_u16(out, 0u);               // disk number
        put_u16(out, 0u);               // central directory start disk
        put_u16(out, count16);          // entries on this disk
        put_u16(out, count16);          // total entries
        put_u32(out, cd_size);
        put_u32(out, cd_offset);
        put_u16(out, 0u);               // comment length

        return out;
    }

private:
    struct entry {
        std::string name;
        std::string data;
        uint32_t    crc32{0};
    };

    static void put_u16(std::string& out, uint16_t v) {
        out.push_back(static_cast<char>(v & 0xFFu));
        out.push_back(static_cast<char>((v >> 8) & 0xFFu));
    }

    static void put_u32(std::string& out, uint32_t v) {
        out.push_back(static_cast<char>(v & 0xFFu));
        out.push_back(static_cast<char>((v >> 8) & 0xFFu));
        out.push_back(static_cast<char>((v >> 16) & 0xFFu));
        out.push_back(static_cast<char>((v >> 24) & 0xFFu));
    }

    static void encode_dos_datetime(std::time_t ts, uint16_t& dos_time, uint16_t& dos_date) {
        std::tm utc{};
#ifdef _WIN32
        if (gmtime_s(&utc, &ts) != 0) {
            dos_time = 0;
            dos_date = (1u << 5) | 1u;  // 1980-01-01
            return;
        }
#else
        if (!gmtime_r(&ts, &utc)) {
            dos_time = 0;
            dos_date = (1u << 5) | 1u;
            return;
        }
#endif
        const int year = utc.tm_year + 1900;
        const uint16_t y = static_cast<uint16_t>(year < 1980 ? 0 : (year > 2107 ? 127 : year - 1980));
        const uint16_t m = static_cast<uint16_t>(utc.tm_mon + 1);
        const uint16_t d = static_cast<uint16_t>(utc.tm_mday);
        const uint16_t hh = static_cast<uint16_t>(utc.tm_hour);
        const uint16_t mm = static_cast<uint16_t>(utc.tm_min);
        const uint16_t ss = static_cast<uint16_t>(utc.tm_sec / 2);
        dos_date = static_cast<uint16_t>((y << 9) | (m << 5) | d);
        dos_time = static_cast<uint16_t>((hh << 11) | (mm << 5) | ss);
    }

    uint16_t           dos_time_{0};
    uint16_t           dos_date_{0};
    std::vector<entry> entries_;
};

} // namespace clew
