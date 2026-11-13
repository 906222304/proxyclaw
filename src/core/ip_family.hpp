#pragma once

// Address-family helpers for WinDivert SOCKET events.
//
// WinDivert reports socket addresses as four host-order 32-bit words, least
// significant word first. IPv4 is carried as an IPv4-mapped IPv6 address:
// [0] = the IPv4 address, [1] = 0x0000FFFF, [2] = [3] = 0. The TCP/UDP
// decision path (CIDR policy, PortTracker, relay) only understands IPv4 and
// reads word [0]. A real IPv6 remote would therefore be evaluated as the
// IPv4 address formed by its low 32 bits, so IPv6 flows are kept out of the
// decision path entirely until IPv6 proxying exists (they go direct).
//
// A dual-stack socket connecting to an IPv4-mapped address is IPv4 traffic
// on the wire and stays managed, whichever layer flag WinDivert sets.

#include <array>
#include <cstdint>

namespace clew {

inline bool is_ipv4_mapped(const uint32_t addr[4]) noexcept {
    return addr[1] == 0x0000FFFFu && addr[2] == 0 && addr[3] == 0;
}

// True for an event ProxyClaw does not manage: IPv6 layer and a remote that
// is not IPv4-mapped.
inline bool is_unmanaged_ipv6(bool ipv6_flag, const uint32_t remote[4]) noexcept {
    return ipv6_flag && !is_ipv4_mapped(remote);
}

// IPv6 address bytes in network order from a WinDivert SOCKET address
// (host-order words, least significant word first).
inline std::array<uint8_t, 16> ipv6_bytes_from_socket(const uint32_t w[4]) noexcept {
    std::array<uint8_t, 16> b{};
    for (int i = 0; i < 4; ++i) {
        const uint32_t v = w[3 - i];
        b[i * 4 + 0] = static_cast<uint8_t>(v >> 24);
        b[i * 4 + 1] = static_cast<uint8_t>(v >> 16);
        b[i * 4 + 2] = static_cast<uint8_t>(v >> 8);
        b[i * 4 + 3] = static_cast<uint8_t>(v);
    }
    return b;
}

// Destinations that stay on the local network: link-local (fe80::/10),
// unique local (fc00::/7), multicast (ff00::/8), :: and ::1. The IPv6 block
// never touches them, the way the default exclude CIDRs keep private IPv4
// ranges direct. `b` is 16 bytes in network order.
inline bool is_local_scope_ipv6(const uint8_t* b) noexcept {
    if (b[0] == 0xff) return true;
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return true;
    if ((b[0] & 0xfe) == 0xfc) return true;
    for (int i = 0; i < 15; ++i)
        if (b[i] != 0) return false;
    return b[15] <= 1;
}

} // namespace clew
