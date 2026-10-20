#pragma once

// Keep the acceptor side local. Reflecting a public peer into an inbound
// connection makes stream callouts inspect a fabricated remote connection;
// some Windows network filters abort it immediately on a physical adapter.
// The app still sees its original peer: restore that tuple on replies only.
#include <winsock2.h>
#include <windows.h>
#include <windivert.h>
#include <string>
#include "core/port_tracker.hpp"

namespace clew {

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
    const auto flow = tracker.take(port);
    if (!flow || flow->entry.remote_addr[0] != ntohl(ip->DstAddr) ||
        flow->entry.remote_port != ntohs(tcp->DstPort)) return false;

    tracker.remember_redirect_route(port, ip->SrcAddr,
                                    address->Network.IfIdx, address->Network.SubIfIdx);
    // Src=AppIP:AppPort, Dst=AppIP:ListenerPort. This must be injected
    // outbound: Windows loopback packets cannot be injected inbound.
    ip->DstAddr = ip->SrcAddr;
    tcp->DstPort = htons(listener_port);
    address->Outbound = 1;
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
    const auto flow = tracker.take(port);
    if (!flow) return false;
    const auto route = tracker.redirect_route(port);
    if (!route.if_index || ip->SrcAddr != route.local_addr ||
        ip->DstAddr != route.local_addr) return false;

    ip->SrcAddr = htonl(flow->entry.remote_addr[0]);
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
