#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace clew::dns_wire {
inline uint16_t u16(const uint8_t* p) { return uint16_t(uint16_t(p[0]) << 8 | p[1]); }
inline void set_id(std::vector<uint8_t>& p, uint16_t id) {
    p[0] = static_cast<uint8_t>(id >> 8);
    p[1] = static_cast<uint8_t>(id);
}
// Follow compression pointers with bounded hops, retaining the next field position.
inline bool name(std::span<const uint8_t> p, size_t& pos, std::string& key) {
    size_t cursor = pos, length = 0;
    bool jumped = false;
    for (size_t hops = 0; hops < 128; ++hops) {
        if (cursor >= p.size())
            return false;
        uint8_t n = p[cursor++];
        if ((n & 0xc0) == 0xc0) {
            if (cursor >= p.size())
                return false;
            size_t target = size_t(n & 0x3f) << 8 | p[cursor++];
            if (!jumped)
                pos = cursor;
            jumped = true;
            cursor = target;
            continue;
        }
        if (n > 63 || cursor + n > p.size())
            return false;
        length += size_t(n) + 1;
        if (length > 255)
            return false;
        key.push_back(static_cast<char>(n));
        for (size_t i = 0; i < n; ++i) {
            auto c = p[cursor++];
            key.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c));
        }
        if (!jumped)
            pos = cursor;
        if (!n)
            return true;
    }
    return false;
}
struct questions {
    std::string key;
    size_t end = 12;
};
inline std::optional<questions> parse_questions(std::span<const uint8_t> p) {
    if (p.size() < 12)
        return std::nullopt;
    auto count = u16(p.data() + 4);
    if (!count || count > 16)
        return std::nullopt;
    questions q;
    for (uint16_t i = 0; i < count; ++i) {
        if (!name(p, q.end, q.key) || q.end + 4 > p.size())
            return std::nullopt;
        q.key.append(reinterpret_cast<const char*>(p.data() + q.end), 4);
        q.end += 4;
    }
    return q;
}
inline bool matches(std::span<const uint8_t> r, std::span<const uint8_t> q) {
    if (r.size() < 12 || q.size() < 12 || !(r[2] & 0x80) || u16(r.data()) != u16(q.data()) ||
        (r[2] & 0x78) != (q[2] & 0x78) || u16(r.data() + 4) != u16(q.data() + 4))
        return false;
    auto rq = parse_questions(r), qq = parse_questions(q);
    return rq && qq && rq->key == qq->key;
}
// Keep opcode, RD, CD and questions; discard other sections.
inline std::vector<uint8_t> empty_response(std::span<const uint8_t> q, uint8_t rcode,
                                           bool tc = false) {
    auto info = parse_questions(q);
    if (!info)
        return {};
    std::vector<uint8_t> r(q.begin(), q.begin() + info->end);
    r[2] = static_cast<uint8_t>((q[2] & 0x79) | 0x80 | (tc ? 2 : 0));
    r[3] = static_cast<uint8_t>((q[3] & 0x10) | 0x80 | rcode);
    for (size_t i = 6; i < 12; ++i)
        r[i] = 0;
    return r;
}
// Respect the client's EDNS UDP size when returning an upstream TCP answer.
inline size_t udp_limit(std::span<const uint8_t> q) {
    auto info = parse_questions(q);
    if (!info)
        return 512;
    size_t pos = info->end;
    uint32_t before_opt = uint32_t(u16(q.data() + 6)) + u16(q.data() + 8);
    uint32_t count = before_opt + u16(q.data() + 10);
    for (uint32_t i = 0; i < count; ++i) {
        std::string ignored;
        if (!name(q, pos, ignored) || pos + 10 > q.size())
            break;
        auto type = u16(q.data() + pos), cls = u16(q.data() + pos + 2),
             len = u16(q.data() + pos + 8);
        pos += 10;
        if (pos + len > q.size())
            break;
        if (i >= before_opt && type == 41)
            return cls < 512 ? 512 : (cls > 65507 ? 65507 : cls);
        pos += len;
    }
    return 512;
}
} // namespace clew::dns_wire
