#pragma once

// UdpPortTracker: two 65536-slot arrays (IPv4, IPv6) for O(1) lock-free UDP
// (family, port)->decision mapping.
// Independent from TCP PortTracker — separate memory, separate lifetime.
//
// Synchronization model (mirrors TCP PortTracker):
//   Writer: UDP SOCKET handler (strand, single thread)
//   Reader: UDP NETWORK worker threads (2, read-only check)
//   Guarantee: release/acquire on atomic<bool> ensures complete entry visibility

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <optional>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "rules/policy_table.hpp"

namespace clew {

struct UdpTrackerEntry {
    uint32_t group_id{0};
    uint32_t pid{0};                              // needed for SOCKS5 session routing
    uint32_t policy_id{GLOBAL_ONLY_POLICY};       // row in the published PolicyTable
};

// Slots are published lock-free: the writer fills the entry and then flips
// `active` with release semantics, and there is nothing stopping the writer
// from overwriting a slot a reader is still copying. That is only survivable
// while a torn read costs at most one misrouted packet, which requires the
// entry to be plain bytes. A member with a non-trivial copy (shared_ptr,
// string, vector) turns the same race into heap corruption. Heap-owned policy
// data belongs in the generation-versioned PolicyTable; keep an id here.
static_assert(std::is_trivially_copyable_v<UdpTrackerEntry>,
              "UdpTrackerEntry must stay trivially copyable — see the comment above");

// A port is empty (no decision seen since its last CLOSE), direct (BIND seen,
// not proxied, or pinned direct by the first-packet watchdog) or proxied.
// The NETWORK layer parks datagrams of empty ports (udp_first_packet.hpp).
enum class udp_slot_state : uint8_t { empty = 0, direct = 1, proxied = 2 };

// UDP port numbers are per address family: an IPv4 socket and an IPv6-only
// socket of two different processes can hold the same port at once. Each
// family keeps its own slot, so one socket's BIND / CLOSE never overwrites
// or clears the other's decision.
enum class udp_family : uint8_t { v4 = 0, v6 = 1 };

struct alignas(64) UdpTrackerSlot {
    std::atomic<udp_slot_state> state{udp_slot_state::empty};
    uint32_t owner_pid{0};                        // strand only (clear())
    UdpTrackerEntry entry{};
};

class UdpPortTracker {
public:
    // Write entry (called from UDP SOCKET handler on strand)
    void put(udp_family f, uint16_t src_port, const UdpTrackerEntry& e) {
        auto& slot = at(f, src_port);
        slot.entry = e;
        slot.owner_pid = e.pid;
        slot.state.store(udp_slot_state::proxied, std::memory_order_release);
    }

    // Decision "not proxied" (called from UDP SOCKET handler on strand).
    void put_direct(udp_family f, uint16_t src_port, uint32_t pid) {
        auto& slot = at(f, src_port);
        slot.owner_pid = pid;
        slot.state.store(udp_slot_state::direct, std::memory_order_release);
    }

    // First-packet watchdog: a port still without a decision is pinned direct
    // so its later datagrams are not parked again. Loses to a real decision.
    bool pin_direct_if_empty(udp_family f, uint16_t src_port) {
        if (at(other(f), src_port).state.load(std::memory_order_acquire) != udp_slot_state::empty)
            return false;   // decided through the dual-stack fallback
        auto expected = udp_slot_state::empty;
        return at(f, src_port).state.compare_exchange_strong(
            expected, udp_slot_state::direct, std::memory_order_acq_rel);
    }

    // The state a datagram of family `f` follows: its own family's slot, or,
    // while that one is empty, the other family's. A dual-stack socket is
    // bound on the IPv6 layer and still sends IPv4, so its IPv4 datagrams
    // follow the BIND decision until a CONNECT decides IPv4 itself.
    udp_slot_state state(udp_family f, uint16_t port) const {
        const auto own = at(f, port).state.load(std::memory_order_acquire);
        if (own != udp_slot_state::empty) return own;
        return at(other(f), port).state.load(std::memory_order_acquire);
    }

    bool decided(udp_family f, uint16_t port) const {
        return state(f, port) != udp_slot_state::empty;
    }

    // Proxied for family `f` (own slot, else the fallback above).
    bool is_active(udp_family f, uint16_t port) const {
        return state(f, port) == udp_slot_state::proxied;
    }

    // Proxied in either family (the UI's connection rows).
    bool is_active(uint16_t port) const {
        return at(udp_family::v4, port).state.load(std::memory_order_acquire) == udp_slot_state::proxied ||
               at(udp_family::v6, port).state.load(std::memory_order_acquire) == udp_slot_state::proxied;
    }

    // Read the own-family entry without consuming (tests).
    const UdpTrackerEntry& peek(udp_family f, uint16_t port) const {
        return at(f, port).entry;
    }

    // Entry for a datagram of family `f`, if the slot it follows is proxied.
    std::optional<UdpTrackerEntry> get(udp_family f, uint16_t port) const {
        const auto& own = at(f, port);
        const auto s = own.state.load(std::memory_order_acquire);
        if (s == udp_slot_state::proxied) return own.entry;
        if (s != udp_slot_state::empty) return std::nullopt;
        const auto& alt = at(other(f), port);
        if (alt.state.load(std::memory_order_acquire) == udp_slot_state::proxied)
            return alt.entry;
        return std::nullopt;
    }

    // CLOSE of a socket of family `f` owned by `pid` (strand). Clears that
    // family's slot; the other family's only when the same process wrote it
    // (a dual-stack socket decided IPv4 by a CONNECT), never another
    // process's socket that happens to share the port number.
    void clear(udp_family f, uint16_t port, uint32_t pid) {
        reset(at(f, port));
        auto& alt = at(other(f), port);
        if (pid != 0 && alt.owner_pid == pid) reset(alt);
    }

private:
    std::array<std::array<UdpTrackerSlot, 65536>, 2> slots_{};

    static udp_family other(udp_family f) {
        return f == udp_family::v4 ? udp_family::v6 : udp_family::v4;
    }
    UdpTrackerSlot& at(udp_family f, uint16_t port) {
        return slots_[static_cast<size_t>(f)][port];
    }
    const UdpTrackerSlot& at(udp_family f, uint16_t port) const {
        return slots_[static_cast<size_t>(f)][port];
    }
    static void reset(UdpTrackerSlot& slot) {
        slot.state.store(udp_slot_state::empty, std::memory_order_release);
        slot.entry = UdpTrackerEntry{};
        slot.owner_pid = 0;
    }
};

} // namespace clew
