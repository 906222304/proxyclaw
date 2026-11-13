#pragma once

// WinDivert NETWORK layer for outbound IPv6 TCP SYNs (ipv6_gate.hpp).
//
// Only the initial SYN of non-loopback IPv6 connections is diverted, so the
// cost is one user-mode round trip per IPv6 connection attempt. A SYN whose
// port the SOCKET layer marked `block` is answered with an inbound RST and
// dropped; `allow` re-injects it unchanged; a SYN with no verdict yet is
// parked until the verdict arrives (SOCKET strand -> on_decided()) or the
// watchdog lets it through after `park_deadline` (fail open, like the IPv4
// SYN watchdog).

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
#include <thread>
#include <vector>

#include "core/ipv6_gate.hpp"
#include "core/log.hpp"

namespace clew {

class windivert_network_v6 {
public:
    explicit windivert_network_v6(std::chrono::milliseconds park_deadline = std::chrono::milliseconds{20})
        : park_deadline_(std::max(std::chrono::milliseconds{5}, park_deadline)) {}

    ~windivert_network_v6() { close(); }

    HANDLE handle() const { return handle_; }

    bool open() {
        const char* filter = "ipv6 and outbound and !loopback and tcp and tcp.Syn and !tcp.Ack";
        handle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle_ == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[WD-NET-V6] Open failed: {}", GetLastError());
            return false;
        }
        PC_LOG_INFO("[WD-NET-V6] Opened (filter: {})", filter);
        return true;
    }

    void start() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        running_ = true;
        worker_   = std::jthread([this](std::stop_token st) { worker_loop(st); });
        watchdog_ = std::jthread([this](std::stop_token st) { watchdog_loop(st); });
        PC_LOG_INFO("[WD-NET-V6] started (park deadline {} ms)", park_deadline_.count());
    }

    // SOCKET strand: the verdict for an IPv6 CONNECT on `port`.
    void on_decided(uint16_t port, v6_verdict v) {
        auto parked = (v == v6_verdict::none)
                          ? gate_.clear(port)
                          : gate_.decide(port, v, std::chrono::steady_clock::now());
        if (parked.empty() || handle_ == INVALID_HANDLE_VALUE) return;
        released_decision_.fetch_add(parked.size(), std::memory_order_relaxed);
        for (auto& p : parked) act(v == v6_verdict::block ? v6_verdict::block : v6_verdict::allow, p);
    }

    // Shutdown phase 1 (see windivert_network::stop_workers).
    void stop_workers() {
        if (workers_stopped_) return;
        workers_stopped_ = true;
        if (handle_ != INVALID_HANDLE_VALUE && worker_.joinable()) {
            if (!WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_RECV)) {
                PC_LOG_ERROR("[WD-NET-V6] WinDivertShutdown failed: {}", GetLastError());
                worker_.request_stop();
                WinDivertClose(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }
        if (worker_.joinable()) worker_.join();
        running_ = false;
        if (watchdog_.joinable()) { watchdog_.request_stop(); watchdog_.join(); }
        // Nothing may stay parked: let it through.
        if (handle_ != INVALID_HANDLE_VALUE) {
            for (auto& [port, packets] : gate_.expire(std::chrono::steady_clock::time_point::max(),
                                                      std::chrono::steady_clock::duration::zero()))
                for (auto& p : packets) send(p);
        }
    }

    void close() {
        stop_workers();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            PC_LOG_INFO("[WD-NET-V6] Closed (blocked={}, allowed={}, parked={}, watchdog={})",
                        blocked_.load(), allowed_.load(), parked_.load(), released_watchdog_.load());
        }
    }

    uint64_t blocked() const { return blocked_.load(std::memory_order_relaxed); }
    uint64_t allowed() const { return allowed_.load(std::memory_order_relaxed); }
    uint64_t parked() const { return parked_.load(std::memory_order_relaxed); }
    uint64_t released_by_watchdog() const { return released_watchdog_.load(std::memory_order_relaxed); }

private:
    struct packet {
        std::vector<uint8_t> bytes;
        WINDIVERT_ADDRESS    addr{};
    };

    std::chrono::milliseconds park_deadline_;
    ipv6_tcp_gate<packet> gate_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    std::atomic<bool> running_{false};
    bool workers_stopped_{false};
    std::jthread worker_;
    std::jthread watchdog_;

    std::atomic<uint64_t> blocked_{0};
    std::atomic<uint64_t> allowed_{0};
    std::atomic<uint64_t> parked_{0};
    std::atomic<uint64_t> released_decision_{0};
    std::atomic<uint64_t> released_watchdog_{0};

    void send(const packet& p) {
        WinDivertSend(handle_, p.bytes.data(), static_cast<UINT>(p.bytes.size()), nullptr, &p.addr);
        allowed_.fetch_add(1, std::memory_order_relaxed);
    }

    // Refuse the SYN: an RST|ACK goes back to the application, the SYN is
    // dropped. A SYN we cannot answer (extension headers) is dropped too:
    // the application then times out instead of leaking direct.
    void reject(const packet& p) {
        uint8_t rst[IPV6_RST_LEN];
        if (build_ipv6_tcp_rst(p.bytes.data(), p.bytes.size(), rst) != 0) {
            WINDIVERT_ADDRESS a = p.addr;
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

    void act(v6_verdict v, const packet& p) {
        if (v == v6_verdict::block) reject(p);
        else send(p);
    }

    void handle(packet& p) {
        PWINDIVERT_IPV6HDR ip6 = nullptr;
        PWINDIVERT_TCPHDR tcp = nullptr;
        WinDivertHelperParsePacket(p.bytes.data(), static_cast<UINT>(p.bytes.size()),
                                   nullptr, &ip6, nullptr, nullptr, nullptr,
                                   &tcp, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ip6 || !tcp) { send(p); return; }
        const uint16_t port = ntohs(tcp->SrcPort);
        const auto now = std::chrono::steady_clock::now();
        auto v = gate_.lookup(port, now);
        if (v == v6_verdict::none) {
            switch (gate_.park(port, p, now)) {
            case udp_park_result::parked:
                parked_.fetch_add(1, std::memory_order_relaxed);
                return;
            case udp_park_result::full:
                send(p);
                return;
            case udp_park_result::decided:
                v = gate_.lookup(port, std::chrono::steady_clock::now());
                break;
            }
        }
        act(v, p);
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
            packet p{std::vector<uint8_t>(buf.begin(), buf.begin() + len), addr};
            handle(p);
        }
    }

    void watchdog_loop(std::stop_token st) {
        const auto tick = std::max(std::chrono::milliseconds{1}, park_deadline_ / 4);
        while (!st.stop_requested() && running_) {
            std::this_thread::sleep_for(tick);
            for (auto& [port, packets] : gate_.expire(std::chrono::steady_clock::now(), park_deadline_)) {
                released_watchdog_.fetch_add(packets.size(), std::memory_order_relaxed);
                for (auto& p : packets) send(p);
            }
        }
    }
};

} // namespace clew
