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

} // namespace clew
