#pragma once

// UDP first-packet parking: the UDP counterpart of TCP SYN parking.
//
// The SOCKET layer learns about a UDP socket from its BIND event, which
// WinDivert delivers asynchronously (SNIFF). A datagram sent right after an
// implicit bind (sendto() on a fresh socket) can reach the NETWORK layer
// before the strand has published that port's decision, and used to leave
// direct. The NETWORK worker now parks datagrams from a port that has no
// decision yet; publishing the decision releases them (proxied or direct),
// and a watchdog releases anything older than the deadline direct, so a
// socket whose BIND was never seen (opened before ProxyClaw started) costs
// one wait, after which its port is pinned direct.
//
// This header holds only the bookkeeping (no WinDivert), so it is unit
// tested on its own. Packet is whatever the caller needs to re-send.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clew {

struct UdpParkingLimits {
    std::size_t max_total    = 1024;  // datagrams parked across all ports
    std::size_t max_per_port = 64;    // datagrams parked for one port
};

enum class udp_park_result {
    parked,     // held; released later by take() or expire()
    decided,    // the port got its decision meanwhile: handle the packet now
    full,       // over a limit: handle as undecided (send direct)
};

template <typename Packet, typename Clock = std::chrono::steady_clock>
class udp_first_packet_parker {
public:
    using time_point = typename Clock::time_point;

    explicit udp_first_packet_parker(UdpParkingLimits limits = {}) : limits_(limits) {}

    // still_undecided() is evaluated under the lock. A publisher stores the
    // decision before calling take(), which takes the same lock, so either
    // this call sees the decision (returns decided) or take() sees the packet.
    template <typename StillUndecided>
    udp_park_result park(uint16_t port, Packet& packet, time_point now,
                         StillUndecided&& still_undecided) {
        std::lock_guard lock(mu_);
        if (!still_undecided()) return udp_park_result::decided;
        auto& list = parked_[port];
        if (total_ >= limits_.max_total || list.size() >= limits_.max_per_port) {
            if (list.empty()) parked_.erase(port);
            return udp_park_result::full;
        }
        if (list.empty()) oldest_[port] = now;
        list.push_back(std::move(packet));
        ++total_;
        return udp_park_result::parked;
    }

    // Everything parked for `port`, in arrival order.
    std::vector<Packet> take(uint16_t port) {
        std::lock_guard lock(mu_);
        return take_locked(port);
    }

    // Ports whose oldest parked datagram is at least `deadline` old, with
    // their datagrams, in arrival order per port.
    std::vector<std::pair<uint16_t, std::vector<Packet>>> expire(time_point now,
                                                                 typename Clock::duration deadline) {
        std::lock_guard lock(mu_);
        std::vector<uint16_t> due;
        for (const auto& [port, since] : oldest_)
            if (now - since >= deadline) due.push_back(port);
        std::vector<std::pair<uint16_t, std::vector<Packet>>> out;
        out.reserve(due.size());
        for (auto port : due) out.emplace_back(port, take_locked(port));
        return out;
    }

    std::size_t size() const {
        std::lock_guard lock(mu_);
        return total_;
    }

private:
    std::vector<Packet> take_locked(uint16_t port) {
        std::vector<Packet> out;
        auto it = parked_.find(port);
        if (it == parked_.end()) return out;
        out = std::move(it->second);
        parked_.erase(it);
        oldest_.erase(port);
        total_ -= out.size();
        return out;
    }

    UdpParkingLimits limits_;
    mutable std::mutex mu_;
    std::unordered_map<uint16_t, std::vector<Packet>> parked_;
    std::unordered_map<uint16_t, time_point> oldest_;
    std::size_t total_{0};
};

} // namespace clew
