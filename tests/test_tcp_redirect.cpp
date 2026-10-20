// Real WinDivert parsing/checksums, without opening the packet driver.
#include "core/tcp_redirect.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
constexpr uint16_t app_port = 45001, listener_port = 45002;
constexpr uint32_t remote = 0x6812202f;
void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

struct Packet {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(44, 0);
    WINDIVERT_ADDRESS address{};
    PWINDIVERT_IPHDR ip() { return reinterpret_cast<PWINDIVERT_IPHDR>(bytes.data()); }
    PWINDIVERT_TCPHDR tcp() { return reinterpret_cast<PWINDIVERT_TCPHDR>(bytes.data() + 20); }
    Packet(uint32_t source, uint16_t sport, uint32_t destination, uint16_t dport) {
        ip()->Version = 4; ip()->HdrLength = 5; ip()->Length = htons(44);
        ip()->TTL = 128; ip()->Protocol = IPPROTO_TCP;
        ip()->SrcAddr = htonl(source); ip()->DstAddr = htonl(destination);
        tcp()->SrcPort = htons(sport); tcp()->DstPort = htons(dport);
        tcp()->HdrLength = 5; tcp()->Ack = 1;
        bytes[40] = 't'; bytes[41] = 'e'; bytes[42] = 's'; bytes[43] = 't';
        address.Outbound = 1;
        WinDivertHelperCalcChecksums(bytes.data(), UINT(bytes.size()), &address, 0);
    }
    void unchanged_payload() {
        check(std::string(bytes.begin() + 40, bytes.end()) == "test", "payload changed");
        const auto ip_sum = ip()->Checksum, tcp_sum = tcp()->Checksum;
        WinDivertHelperCalcChecksums(bytes.data(), UINT(bytes.size()), &address, 0);
        check(ip_sum == ip()->Checksum && tcp_sum == tcp()->Checksum, "invalid checksums");
    }
};

void round_trip(uint32_t local, uint32_t interface_index) {
    auto tracker = std::make_unique<clew::PortTracker>();
    clew::TrackerEntry entry{}; entry.remote_addr[0] = remote; entry.remote_port = 443;
    tracker->publish(app_port, clew::slot_state::proxied, entry, 1);
    Packet request(local, app_port, remote, 443);
    request.address.Network.IfIdx = interface_index;
    request.address.Network.SubIfIdx = 7;
    check(clew::redirect_tcp_to_local(request.bytes.data(), UINT(request.bytes.size()),
          &request.address, listener_port, *tracker), "forward rejected");
    check(request.ip()->SrcAddr == htonl(local) && request.ip()->DstAddr == htonl(local), "forward must stay local");
    check(ntohs(request.tcp()->DstPort) == listener_port && request.address.Outbound, "wrong forward port/direction");
    request.unchanged_payload();
    Packet reply(local, listener_port, local, app_port);
    reply.address.Loopback = 1; reply.address.Network.IfIdx = 1;
    check(clew::restore_tcp_from_local(reply.bytes.data(), UINT(reply.bytes.size()),
          &reply.address, listener_port, *tracker), "reply rejected");
    check(reply.ip()->SrcAddr == htonl(remote) && reply.ip()->DstAddr == htonl(local), "wrong restored addresses");
    check(ntohs(reply.tcp()->SrcPort) == 443 && ntohs(reply.tcp()->DstPort) == app_port, "wrong restored ports");
    check(!reply.address.Outbound && !reply.address.Loopback, "reply must be inbound to original adapter");
    check(reply.address.Network.IfIdx == interface_index && reply.address.Network.SubIfIdx == 7, "original interface lost");
    reply.unchanged_payload();

    tracker->publish(app_port, clew::slot_state::proxied, entry, 2);
    check(tracker->redirect_route(app_port).if_index == 0, "reused port retained old interface");
    Packet old_reply(local, listener_port, local, app_port);
    check(!clew::restore_tcp_from_local(old_reply.bytes.data(), UINT(old_reply.bytes.size()),
          &old_reply.address, listener_port, *tracker), "old reply reused a new flow route");
    Packet wrong_request(local, app_port, remote, 80);
    check(!clew::redirect_tcp_to_local(wrong_request.bytes.data(), UINT(wrong_request.bytes.size()),
          &wrong_request.address, listener_port, *tracker), "unrelated tuple redirected");
    tracker->publish(app_port, clew::slot_state::direct, entry, 3);
    Packet direct(local, app_port, remote, 443);
    check(!clew::redirect_tcp_to_local(direct.bytes.data(), UINT(direct.bytes.size()),
          &direct.address, listener_port, *tracker), "direct flow redirected");
}
}

int main() {
    try {
        round_trip(0xc000020a, 21);
        round_trip(0xc6120001, 54);
        const auto filter = clew::tcp_redirect_filter(listener_port);
        Packet reply(0xc000020a, listener_port, 0xc000020a, app_port);
        reply.address.Loopback = 1;
        check(WinDivertHelperEvalFilter(filter.c_str(), reply.bytes.data(), UINT(reply.bytes.size()), &reply.address), "loopback reply omitted from filter");
        reply.tcp()->SrcPort = htons(45003);
        check(!WinDivertHelperEvalFilter(filter.c_str(), reply.bytes.data(), UINT(reply.bytes.size()), &reply.address), "ordinary loopback traffic captured");
        reply.address.Loopback = 0;
        check(WinDivertHelperEvalFilter(filter.c_str(), reply.bytes.data(), UINT(reply.bytes.size()), &reply.address), "non-loopback traffic omitted");
        std::cout << "PASS local TCP handoff: physical/TUN tuples, interface, checksums, payload, port reuse, exclusions, filter\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
