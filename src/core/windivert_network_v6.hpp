#pragma once

// WinDivert NETWORK layer for outbound IPv6 TCP (ipv6_gate.hpp,
// ipv6_flow_table.hpp).
//
// Filter: non-loopback outbound IPv6 TCP, plus the IPv6 acceptor's loopback
// replies. Per packet:
//   - acceptor reply ([::1]:acceptor -> [::1]:AppPort): restored to the
//     original remote tuple, injected inbound on the application's interface;
//   - initial SYN: the SOCKET layer's per-port verdict decides. `proxy`
//     reflects it to [::1]:acceptor (Src = Dst = ::1, the IPv4 path's
//     127.0.0.1 handoff), `block` answers with an inbound RST and drops it,
//     `allow` re-injects it. A SYN with no verdict yet is parked until the
//     verdict arrives (SOCKET strand -> on_decided()) or the watchdog lets it
//     through after `park_deadline` (fail open, like the IPv4 SYN watchdog);
//   - any other segment: reflected when its port has a live or draining
//     proxied flow, otherwise re-injected unchanged (lock-free pre-check).

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "core/ipv6_flow_table.hpp"
#include "core/ipv6_gate.hpp"
#include "core/log.hpp"

namespace clew {

using v6_flows = ipv6_flow_table<>;

inline std::string tcp_redirect_filter_v6(uint16_t acceptor_port) {
    if (acceptor_port == 0)  // no IPv6 acceptor: only the SYN gate (block / allow)
        return "ipv6 and outbound and !loopback and tcp and tcp.Syn and !tcp.Ack";
    return "ipv6 and outbound and tcp and (!loopback or tcp.SrcPort == " +
           std::to_string(acceptor_port) + ")";
}

class windivert_network_v6 {
public:
    // acceptor_port 0: IPv6 proxying unavailable, `proxy` verdicts act as block.
    windivert_network_v6(v6_flows& flows, uint16_t acceptor_port,
                         std::chrono::milliseconds park_deadline = std::chrono::milliseconds{20})
        : flows_(flows), acceptor_port_(acceptor_port)
        , park_deadline_(std::max(std::chrono::milliseconds{5}, park_deadline)) {}

    ~windivert_network_v6() { close(); }

    HANDLE handle() const { return handle_; }
    uint16_t acceptor_port() const { return acceptor_port_; }

    bool open() {
        const auto filter = tcp_redirect_filter_v6(acceptor_port_);
        handle_ = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle_ == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[WD-NET-V6] Open failed: {}", GetLastError());
            return false;
        }
        if (acceptor_port_ != 0) {
            WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
            WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, 2000);
            WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);
        }
        PC_LOG_INFO("[WD-NET-V6] Opened (filter: {})", filter);
        return true;
    }

    void start(int num_workers = 1) {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        running_ = true;
        for (int i = 0; i < num_workers; ++i)
            workers_.emplace_back([this](std::stop_token st) { worker_loop(st); });
        watchdog_ = std::jthread([this](std::stop_token st) { watchdog_loop(st); });
        PC_LOG_INFO("[WD-NET-V6] {} worker(s) started (park deadline {} ms)",
                    num_workers, park_deadline_.count());
    }

    // SOCKET strand: the verdict for an IPv6 CONNECT on `port` (none on
    // CLOSE). For `proxy` the flow is already published in the table.
    void on_decided(uint16_t port, v6_verdict v) {
        auto parked = (v == v6_verdict::none)
                          ? gate_.clear(port)
                          : gate_.decide(port, v, std::chrono::steady_clock::now());
        if (parked.empty() || handle_ == INVALID_HANDLE_VALUE) return;
        released_decision_.fetch_add(parked.size(), std::memory_order_relaxed);
        for (auto& p : parked)
            act(v == v6_verdict::none ? v6_verdict::allow : v, p.bytes.data(),
                static_cast<UINT>(p.bytes.size()), p.addr);
    }

    // Shutdown phase 1 (see windivert_network::stop_workers).
    void stop_workers() {
        if (workers_stopped_) return;
        workers_stopped_ = true;
        if (handle_ != INVALID_HANDLE_VALUE && !workers_.empty()) {
            if (!WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_RECV)) {
                PC_LOG_ERROR("[WD-NET-V6] WinDivertShutdown failed: {}", GetLastError());
                for (auto& w : workers_) w.request_stop();
                WinDivertClose(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }
        for (auto& w : workers_) if (w.joinable()) w.join();
        workers_.clear();
        running_ = false;
        if (watchdog_.joinable()) { watchdog_.request_stop(); watchdog_.join(); }
        // Nothing may stay parked: let it through.
        if (handle_ != INVALID_HANDLE_VALUE) {
            for (auto& [port, packets] : gate_.expire(std::chrono::steady_clock::time_point::max(),
                                                      std::chrono::steady_clock::duration::zero()))
                for (auto& p : packets) send(p.bytes.data(), static_cast<UINT>(p.bytes.size()), p.addr);
        }
    }

    void close() {
        stop_workers();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            PC_LOG_INFO("[WD-NET-V6] Closed (proxied={}, blocked={}, allowed={}, parked={}, watchdog={})",
                        proxied_.load(), blocked_.load(), allowed_.load(), parked_.load(),
                        released_watchdog_.load());
        }
    }

    uint64_t proxied() const { return proxied_.load(std::memory_order_relaxed); }
    uint64_t blocked() const { return blocked_.load(std::memory_order_relaxed); }
    uint64_t allowed() const { return allowed_.load(std::memory_order_relaxed); }
    uint64_t parked() const { return parked_.load(std::memory_order_relaxed); }
    uint64_t released_by_watchdog() const { return released_watchdog_.load(std::memory_order_relaxed); }
    uint64_t nat_count() const { return nat_.load(std::memory_order_relaxed); }

private:
    struct packet {
        std::vector<uint8_t> bytes;
        WINDIVERT_ADDRESS    addr{};
    };

    v6_flows& flows_;
    uint16_t acceptor_port_;
    std::chrono::milliseconds park_deadline_;
    ipv6_tcp_gate<packet> gate_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    std::atomic<bool> running_{false};
    bool workers_stopped_{false};
    std::vector<std::jthread> workers_;
    std::jthread watchdog_;

    std::atomic<uint64_t> proxied_{0};
    std::atomic<uint64_t> blocked_{0};
    std::atomic<uint64_t> allowed_{0};
    std::atomic<uint64_t> parked_{0};
    std::atomic<uint64_t> released_decision_{0};
    std::atomic<uint64_t> released_watchdog_{0};
    std::atomic<uint64_t> nat_{0};

    static constexpr uint8_t LOOPBACK6[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};

    void send(const uint8_t* bytes, UINT len, const WINDIVERT_ADDRESS& addr) {
        WinDivertSend(handle_, bytes, len, nullptr, &addr);
    }

    void allow(const uint8_t* bytes, UINT len, const WINDIVERT_ADDRESS& addr) {
        send(bytes, len, addr);
        allowed_.fetch_add(1, std::memory_order_relaxed);
    }

    // Refuse the SYN: an RST|ACK goes back to the application, the SYN is
    // dropped. A SYN we cannot answer (extension headers) is dropped too:
    // the application then times out instead of leaking direct.
    void reject(const uint8_t* bytes, UINT len, const WINDIVERT_ADDRESS& addr) {
        uint8_t rst[IPV6_RST_LEN];
        if (build_ipv6_tcp_rst(bytes, len, rst) != 0) {
            WINDIVERT_ADDRESS a = addr;
            a.Outbound = 0;
            WinDivertHelperCalcChecksums(rst, sizeof(rst), &a, 0);
            if (!WinDivertSend(handle_, rst, sizeof(rst), nullptr, &a))
                PC_LOG_WARN("[WD-NET-V6] RST inject failed: {}", GetLastError());
            else
                PC_LOG_DEBUG("[WD-NET-V6] SYN refused (RST) if={}.{}", a.Network.IfIdx, a.Network.SubIfIdx);
        } else {
            PC_LOG_DEBUG("[WD-NET-V6] SYN dropped (no RST: extension headers)");
        }
        blocked_.fetch_add(1, std::memory_order_relaxed);
    }

    // App segment -> [::1]:acceptor. Src=Dst=::1, as the IPv4 path uses
    // 127.0.0.1 (see tcp_redirect.hpp for why not the adapter address).
    bool reflect(uint8_t* bytes, UINT len, WINDIVERT_ADDRESS& addr, bool syn) {
        PWINDIVERT_IPV6HDR ip6 = nullptr;
        PWINDIVERT_TCPHDR tcp = nullptr;
        WinDivertHelperParsePacket(bytes, len, nullptr, &ip6, nullptr, nullptr, nullptr,
                                   &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ip6 || !tcp) return false;
        const uint16_t port = ntohs(tcp->SrcPort);
        const auto flow = flows_.find(port, std::chrono::steady_clock::now());
        if (!flow || flow->remote_port != ntohs(tcp->DstPort) ||
            std::memcmp(flow->remote.data(), ip6->DstAddr, 16) != 0) return false;
        if (syn || !flow->has_route)
            flows_.remember_route(port, reinterpret_cast<const uint8_t*>(ip6->SrcAddr),
                                  addr.Network.IfIdx, addr.Network.SubIfIdx);
        std::memcpy(ip6->SrcAddr, LOOPBACK6, 16);
        std::memcpy(ip6->DstAddr, LOOPBACK6, 16);
        tcp->DstPort = htons(acceptor_port_);
        addr.Outbound = 1;
        addr.Loopback = 1;
        WinDivertHelperCalcChecksums(bytes, len, &addr, 0);
        send(bytes, len, addr);
        nat_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // [::1]:acceptor -> [::1]:AppPort, restored to Remote -> App, inbound on
    // the application's interface.
    bool restore(uint8_t* bytes, UINT len, WINDIVERT_ADDRESS& addr,
                 PWINDIVERT_IPV6HDR ip6, PWINDIVERT_TCPHDR tcp) {
        if (std::memcmp(ip6->SrcAddr, LOOPBACK6, 16) != 0 ||
            std::memcmp(ip6->DstAddr, LOOPBACK6, 16) != 0) return false;
        const auto flow = flows_.find(ntohs(tcp->DstPort), std::chrono::steady_clock::now());
        if (!flow || !flow->has_route) return false;
        std::memcpy(ip6->SrcAddr, flow->remote.data(), 16);
        std::memcpy(ip6->DstAddr, flow->local.data(), 16);
        tcp->SrcPort = htons(flow->remote_port);
        addr.Outbound = 0;
        addr.Loopback = 0;
        addr.Network.IfIdx = flow->if_idx;
        addr.Network.SubIfIdx = flow->sub_if_idx;
        WinDivertHelperCalcChecksums(bytes, len, &addr, 0);
        send(bytes, len, addr);
        nat_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Act on a SYN's verdict. `bytes` may be rewritten in place.
    void act(v6_verdict v, uint8_t* bytes, UINT len, WINDIVERT_ADDRESS addr) {
        switch (v) {
        case v6_verdict::proxy:
            if (acceptor_port_ != 0 && reflect(bytes, len, addr, /*syn=*/true)) {
                proxied_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            // No flow (or no acceptor): never leak a proxied process direct.
            reject(bytes, len, addr);
            return;
        case v6_verdict::block:
            reject(bytes, len, addr);
            return;
        default:
            allow(bytes, len, addr);
            return;
        }
    }

    void handle(uint8_t* bytes, UINT len, WINDIVERT_ADDRESS& addr) {
        PWINDIVERT_IPV6HDR ip6 = nullptr;
        PWINDIVERT_TCPHDR tcp = nullptr;
        WinDivertHelperParsePacket(bytes, len, nullptr, &ip6, nullptr, nullptr, nullptr,
                                   &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ip6 || !tcp) { send(bytes, len, addr); return; }
        const uint16_t sport = ntohs(tcp->SrcPort);

        if (addr.Loopback) {
            // Only the acceptor's replies are diverted on loopback.
            if (!(acceptor_port_ != 0 && sport == acceptor_port_ && restore(bytes, len, addr, ip6, tcp)))
                send(bytes, len, addr);
            return;
        }

        if (tcp->Syn && !tcp->Ack) {
            const auto now = std::chrono::steady_clock::now();
            auto v = gate_.lookup(sport, now);
            if (v == v6_verdict::none) {
                packet p{std::vector<uint8_t>(bytes, bytes + len), addr};
                switch (gate_.park(sport, p, now)) {
                case udp_park_result::parked:
                    parked_.fetch_add(1, std::memory_order_relaxed);
                    return;
                case udp_park_result::full:
                    allow(bytes, len, addr);
                    return;
                case udp_park_result::decided:
                    v = gate_.lookup(sport, std::chrono::steady_clock::now());
                    break;
                }
            }
            act(v, bytes, len, addr);
            return;
        }

        if (flows_.maybe_ours(sport) && reflect(bytes, len, addr, /*syn=*/false)) return;
        send(bytes, len, addr);
    }

    void worker_loop(std::stop_token st) {
        std::vector<uint8_t> buf(65535);
        uint32_t recv_errors = 0;
        while (!st.stop_requested()) {
            WINDIVERT_ADDRESS addr{};
            UINT len = 0;
            if (!WinDivertRecv(handle_, buf.data(), static_cast<UINT>(buf.size()), &len, &addr)) {
                const DWORD err = GetLastError();
                if (err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE) break;
                if ((recv_errors++ & 1023) == 0)
                    PC_LOG_WARN("[WD-NET-V6] Recv error {} (x{})", err, recv_errors);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            handle(buf.data(), len, addr);
        }
    }

    void watchdog_loop(std::stop_token st) {
        const auto tick = std::max(std::chrono::milliseconds{1}, park_deadline_ / 4);
        while (!st.stop_requested() && running_) {
            std::this_thread::sleep_for(tick);
            for (auto& [port, packets] : gate_.expire(std::chrono::steady_clock::now(), park_deadline_)) {
                released_watchdog_.fetch_add(packets.size(), std::memory_order_relaxed);
                for (auto& p : packets) allow(p.bytes.data(), static_cast<UINT>(p.bytes.size()), p.addr);
            }
        }
    }
};

} // namespace clew
