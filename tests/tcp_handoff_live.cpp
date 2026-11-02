// Administrator-only integration host. Captures only the reserved client-port
// range and one destination tuple; uses production NAT helpers and SOCKS relay.
#include "proxy/relay.hpp"
#include "core/tcp_redirect.hpp"
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 6) return 2;
    struct Logging {
        Logging() {
            quill::Backend::start();
            auto sink = quill::Frontend::create_or_get_sink<quill::ConsoleSink>("live-console");
            clew::g_logger = quill::Frontend::create_or_get_logger("tcp-handoff-live", std::move(sink));
            clew::g_logger->set_log_level(quill::LogLevel::Warning);
        }
        ~Logging() { quill::Backend::stop(); }
    } logging;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) return 2;
    const auto base = static_cast<uint16_t>(std::stoi(argv[1]));
    const int count = std::stoi(argv[2]);
    const auto proxy_port = static_cast<uint16_t>(std::stoi(argv[3]));
    const auto target = asio::ip::make_address_v4(argv[4]);
    auto tracker = std::make_unique<clew::PortTracker>();
    LARGE_INTEGER timestamp{};
    QueryPerformanceCounter(&timestamp);
    clew::TrackerEntry entry{};
    entry.remote_addr[0] = target.to_uint();
    entry.remote_port = 443;
    for (int n = 0; n < count; ++n)
        tracker->publish(uint16_t(base + n), clew::slot_state::proxied,
                         entry, timestamp.QuadPart);
    asio::io_context ioc;
    auto domain = asio::make_strand(ioc);
    std::unordered_map<uint32_t, clew::ProxyGroupConfig> groups{
        {0, {"127.0.0.1", proxy_port}}};
    asio::ip::tcp::acceptor acceptor(ioc,
        {asio::ip::address_v4::loopback(), 0});
    const auto listener = acceptor.local_endpoint().port();
    std::atomic<int> completed{}, exceptions{}, send_errors{};
    std::atomic<bool> running{true};
    auto accept = [&]() -> asio::awaitable<void> {
        for (int n = 0; n < count; ++n) {
            auto sock = co_await acceptor.async_accept(asio::use_awaitable);
            asio::co_spawn(asio::make_strand(ioc),
                clew::handle_connection(std::move(sock), *tracker, domain, groups),
                [&](std::exception_ptr error) {
                    if (error) ++exceptions;
                    ++completed;
                });
        }
    };
    const auto filter = std::format(
        "outbound and ip and tcp and ((ip.DstAddr == {} and tcp.DstPort == 443 "
        "and tcp.SrcPort >= {} and tcp.SrcPort < {}) or "
        "(loopback and tcp.SrcPort == {} and tcp.DstPort >= {} and tcp.DstPort < {}))",
        target.to_string(), base, base + count, listener, base, base + count);
    HANDLE handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 500, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed: " << GetLastError() << '\n';
        return 3;
    }
    std::vector<std::jthread> network;
    for (int n = 0; n < 2; ++n) network.emplace_back([&] {
        uint8_t packet[65535]; WINDIVERT_ADDRESS address{}; UINT size{};
        while (running && WinDivertRecv(handle, packet, sizeof(packet), &size, &address)) {
            if (!clew::restore_tcp_from_local(packet, size, &address, listener, *tracker))
                clew::redirect_tcp_to_local(packet, size, &address, listener, *tracker);
            if (!WinDivertSend(handle, packet, size, nullptr, &address)) ++send_errors;
        }
    });
    asio::co_spawn(ioc, accept(), asio::detached);
    std::vector<std::jthread> workers;
    for (int n = 0; n < 4; ++n) workers.emplace_back([&] { ioc.run(); });
    std::ofstream(std::string(argv[5]) + ".ready") << listener;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(50);
    while (completed != count && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    running = false;
    WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV);
    network.clear();
    WinDivertClose(handle);
    ioc.stop(); workers.clear();
    std::ofstream(std::string(argv[5]) + ".result")
        << completed << ' ' << exceptions << ' ' << send_errors;
    WSACleanup();
    return completed == count && exceptions == 0 && send_errors == 0 ? 0 : 1;
}
