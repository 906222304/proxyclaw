#pragma once

// Use an actual localhost tuple for the acceptor side. Using the physical
// adapter address as both endpoints creates a loopback flow which third-party
// ALE callouts can still treat as a redirected external connection. On endpoint
// cleanup that path can synchronously reinject while the TCP lock is held.
// The application keeps its original tuple; restore both addresses on replies.
#include <winsock2.h>
#include <windows.h>
#include <windivert.h>
#include <string>
#include "core/port_tracker.hpp"

namespace clew {

inline uint32_t tcp_handoff_address() { return htonl(INADDR_LOOPBACK); }

inline std::string tcp_redirect_filter(uint16_t listener_port) {
    // Ordinary local traffic stays outside the interceptor. Only the local
    // acceptor's replies need the loopback branch of this filter.
    return "outbound and tcp and (!loopback or tcp.SrcPort == " +
           std::to_string(listener_port) + ")";
}

inline bool redirect_tcp_to_local(uint8_t* packet, UINT length,
                                  WINDIVERT_ADDRESS* address,
                                  uint16_t listener_port, PortTracker& tracker) {
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    WinDivertHelperParsePacket(packet, length, &ip, nullptr, nullptr, nullptr,
                               nullptr, &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!ip || !tcp) return false;
    const uint16_t port = ntohs(tcp->SrcPort);
    // A new SYN must wait for its own decision, even if this port still has
    // the previous connection's FIN/ACK tombstone.
    if (tcp->Syn && !tcp->Ack && !tracker.take(port)) return false;
    const auto flow = tracker.take_for_packet(port, address->Timestamp);
    if (!flow || flow->entry.remote_addr[0] != ntohl(ip->DstAddr) ||
        flow->entry.remote_port != ntohs(tcp->DstPort)) return false;

    tracker.remember_redirect_route(port, ip->SrcAddr,
                                    address->Network.IfIdx, address->Network.SubIfIdx);
    // Src=127.0.0.1:AppPort, Dst=127.0.0.1:ListenerPort. Preserve AppIP in
    // the route above, not in the synthetic local connection. In particular,
    // changing only DstAddr leaves the physical-address ALE cleanup path alive.
    ip->SrcAddr = tcp_handoff_address();
    ip->DstAddr = tcp_handoff_address();
    tcp->DstPort = htons(listener_port);
    address->Outbound = 1;
    address->Loopback = 1;
    WinDivertHelperCalcChecksums(packet, length, address, 0);
    return true;
}

inline bool restore_tcp_from_local(uint8_t* packet, UINT length,
                                   WINDIVERT_ADDRESS* address,
                                   uint16_t listener_port, const PortTracker& tracker) {
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    WinDivertHelperParsePacket(packet, length, &ip, nullptr, nullptr, nullptr,
                               nullptr, &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!ip || !tcp || ntohs(tcp->SrcPort) != listener_port) return false;
    const uint16_t port = ntohs(tcp->DstPort);
    const auto flow = tracker.take_for_packet(port, address->Timestamp);
    if (!flow) return false;
    const auto route = tracker.redirect_route(port);
    if (!route.if_index || !route.local_addr ||
        ip->SrcAddr != tcp_handoff_address() ||
        ip->DstAddr != tcp_handoff_address()) return false;

    ip->SrcAddr = htonl(flow->entry.remote_addr[0]);
    ip->DstAddr = route.local_addr;
    tcp->SrcPort = htons(flow->entry.remote_port);
    address->Outbound = 0;
    address->Loopback = 0;
    // A loopback reply carries the loopback interface. The application
    // socket belongs to its original adapter, including when TUN is absent.
    address->Network.IfIdx = route.if_index;
    address->Network.SubIfIdx = route.sub_if_index;
    WinDivertHelperCalcChecksums(packet, length, address, 0);
    return true;
}

} // namespace clew
