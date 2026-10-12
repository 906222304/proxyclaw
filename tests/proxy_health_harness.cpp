// Isolated loopback regression host: actual relay/session code, no driver.
#include "proxy/relay.hpp"
#include "proxy/connection_health.hpp"
#include "udp/socks5_udp_manager.hpp"
#include "udp/udp_session_table.hpp"
#include <iostream>
#include <thread>

using namespace std::chrono_literals;
using asio::ip::tcp;

static void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

asio::awaitable<void> tcp_test(asio::io_context& ioc, uint16_t proxy_port) {
    auto domain = asio::make_strand(ioc);
    clew::PortTracker tracker;
    std::unordered_map<uint32_t, clew::ProxyGroupConfig> groups{{0, {"127.0.0.1", proxy_port}}};
    tcp::acceptor acceptor(co_await asio::this_coro::executor, {tcp::v4(), 0});
    std::cout << "READY " << acceptor.local_endpoint().port() << std::endl;
    auto socket = co_await acceptor.async_accept(asio::use_awaitable);
    auto port = socket.remote_endpoint().port();
    clew::TrackerEntry entry{};
    entry.remote_addr[0] = 0xcb007101;
    entry.remote_port = 443;
    co_await asio::co_spawn(domain, [&]() -> asio::awaitable<void> {
        tracker.publish(port, clew::slot_state::proxied, entry, 1);
        co_return;
    }, asio::use_awaitable);
#ifdef PROXYCLAW_BASELINE
    co_await clew::handle_connection(std::move(socket), tracker, domain, groups);
#else
    co_await clew::handle_connection(std::move(socket), tracker, domain, groups, 150ms);
#endif
    co_await asio::co_spawn(domain, [&]() -> asio::awaitable<void> {
        require(!tracker.take(port), "tracker slot was not cleared");
        co_return;
    }, asio::use_awaitable);
    std::cout << "DONE" << std::endl;
}

asio::awaitable<void> udp_control_test(asio::io_context& ioc, uint16_t proxy_port) {
    auto session = std::make_shared<clew::Socks5UdpSession>(ioc, "127.0.0.1", proxy_port);
#ifdef PROXYCLAW_BASELINE
    require(session->establish(), "UDP setup failed");
#else
    require(co_await session->async_establish(150ms), "UDP setup failed");
#endif
    uint8_t bytes[64];
    std::cout << "READY " << session->local_udp_endpoint().port() << std::endl;
    auto [n, ec] = co_await session->async_recv_udp(bytes, sizeof(bytes));
    (void)n;
    require(bool(ec) && !session->is_alive(), "control loss did not cancel UDP receive");
    session->close();
    std::cout << "DONE" << std::endl;
}

#ifndef PROXYCLAW_BASELINE
asio::awaitable<void> udp_stall_test(asio::io_context& ioc, uint16_t proxy_port, bool stop) {
    std::unordered_map<uint32_t, clew::UdpProxyGroupConfig> groups{{0, {"127.0.0.1", proxy_port}}};
    clew::Socks5UdpManager manager(ioc, groups);
    auto task = manager.get_or_create(41000, 0, stop ? 10s : 150ms);
    auto ticker = [&]() -> asio::awaitable<void> {
        asio::steady_timer timer(co_await asio::this_coro::executor, 30ms);
        co_await timer.async_wait(asio::use_awaitable);
        require(manager.active_count() == 0, "stalled session counted as active");
        if (stop) manager.stop();
        std::cout << "TICK" << std::endl;
    };
    using asio::experimental::awaitable_operators::operator&&;
    auto result = co_await (std::move(task) && ticker());
    require(!result, "stalled setup must fail");
    manager.stop();
    std::cout << "DONE" << std::endl;
}

asio::awaitable<void> udp_cleanup_test(asio::io_context& ioc, uint16_t proxy_port) {
    std::unordered_map<uint32_t, clew::UdpProxyGroupConfig> groups{{0, {"127.0.0.1", proxy_port}}};
    clew::Socks5UdpManager manager(ioc, groups);
    for (int cycle = 0; cycle != 12; ++cycle) {
        std::vector<std::shared_ptr<clew::Socks5UdpSession>> sessions;
        for (uint16_t p = 41000; p != 41008; ++p) {
            auto session = co_await manager.get_or_create(p, 0, 1s);
            require(bool(session), "session recreation failed");
            require(co_await session->async_send_udp({1, 2, 3}), "UDP send failed");
            uint8_t bytes[64]{};
            auto [n, ec] = co_await session->async_recv_udp(bytes, sizeof(bytes));
            require(!ec && n == 3 && bytes[0] == 1, "recreated UDP session cannot receive");
            sessions.push_back(session);
        }
        require(manager.active_count() == 8, "wrong active count");
        require(manager.cleanup_expired() == 0, "healthy active sessions expired");
        require(manager.cleanup_expired(0ms) == 8, "idle sessions not removed");
        require(manager.active_count() == 0, "closed sessions retained");
        // Cancellation handlers must release both control and receive owners.
        std::vector<std::weak_ptr<clew::Socks5UdpSession>> weak(sessions.begin(), sessions.end());
        sessions.clear();
        asio::steady_timer drain(co_await asio::this_coro::executor, 10ms);
        co_await drain.async_wait(asio::use_awaitable);
        for (auto& pointer : weak) require(pointer.expired(), "closed session leaked");
    }
    clew::UdpSessionTable table;
    clew::UdpSession stale{};
    stale.orig_dst_port = htons(443);
    stale.last_active -= 200s;
    table.upsert(41000, stale);
    table.upsert(41001, stale);
    table.touch(41001);
    require(table.cleanup_expired() == 1 && table.lookup(41001).has_value(), "UDP routing cleanup failed");
    manager.stop();
    std::cout << "DONE" << std::endl;
}

asio::awaitable<void> udp_recreate_test(asio::io_context& ioc, uint16_t proxy_port) {
    std::unordered_map<uint32_t, clew::UdpProxyGroupConfig> groups{{0, {"127.0.0.1", proxy_port}}};
    clew::Socks5UdpManager manager(ioc, groups);
    auto first = co_await manager.get_or_create(41000, 0, 1s);
    require(bool(first), "first UDP setup failed");
    std::cout << "READY " << first->local_udp_endpoint().port() << std::endl;
    uint8_t bytes[64]{};
    auto [n, ec] = co_await first->async_recv_udp(bytes, sizeof(bytes));
    (void)n;
    require(bool(ec), "old control connection was not lost");
    auto second = co_await manager.get_or_create(41000, 0, 1s);
    require(second && second != first, "dead session not replaced");
    require(co_await second->async_send_udp({4, 5, 6}), "new UDP session send failed");
    auto reply = co_await second->async_recv_udp(bytes, sizeof(bytes));
    require(!reply.second && reply.first == 3 && bytes[0] == 4, "new UDP session receive failed");
    manager.stop();
    std::cout << "DONE" << std::endl;
}
#endif

int main(int argc, char** argv) {
    try {
        if (argc != 3) return 2;
        asio::io_context ioc;
        std::string mode = argv[1];
        auto proxy_port = static_cast<uint16_t>(std::stoi(argv[2]));
        if (mode == "keepalive") {
            tcp::socket socket(ioc, tcp::v4());
            clew::enable_tcp_keepalive(socket);
            asio::socket_base::keep_alive option;
            socket.get_option(option);
            require(option.value(), "keepalive disabled");
            std::cout << "DONE" << std::endl;
            return 0;
        }
        asio::awaitable<void> task;
        if (mode == "tcp") task = tcp_test(ioc, proxy_port);
        else if (mode == "udp_control") task = udp_control_test(ioc, proxy_port);
#ifndef PROXYCLAW_BASELINE
        else if (mode == "udp_stall" || mode == "udp_stop") task = udp_stall_test(ioc, proxy_port, mode == "udp_stop");
        else if (mode == "udp_cleanup") task = udp_cleanup_test(ioc, proxy_port);
        else if (mode == "udp_recreate") task = udp_recreate_test(ioc, proxy_port);
#endif
        else return 2;
        auto result = asio::co_spawn(asio::make_strand(ioc), std::move(task), asio::use_future);
        // Deliberately use one worker for the stall case: async handshakes
        // must let the timer/status query run even with no spare worker.
        std::thread other;
        if (mode != "udp_stall" && mode != "udp_stop") other = std::thread([&] { ioc.run(); });
        ioc.run();
        if (other.joinable()) other.join();
        result.get();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
