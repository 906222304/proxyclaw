#pragma once

// One strand serializes UDP/TCP operations and cancellation. Control loss
// closes the data socket too, releasing every pending receive.
#define ASIO_STANDALONE
#include <asio.hpp>
#include <atomic>
#include <array>
#include <future>
#include <memory>
#include <string>
#include <vector>
#include "core/log.hpp"
#include "proxy/connection_health.hpp"

namespace clew {
using asio::ip::tcp;
using asio::ip::udp;

class Socks5UdpSession : public std::enable_shared_from_this<Socks5UdpSession> {
public:
    Socks5UdpSession(asio::io_context& ioc, const std::string& host, uint16_t port)
        : ioc_(ioc), strand_(asio::make_strand(ioc)), proxy_host_(host), proxy_port_(port),
          tcp_control_(strand_), udp_data_(strand_) {}

    ~Socks5UdpSession() { close_sockets(); }

    // DNS startup only, before its private io_context worker is started.
    // The production UDP relay uses async_establish, never blocking IO workers.
    bool establish(std::chrono::steady_clock::duration timeout = std::chrono::seconds(10)) {
        if (ioc_.stopped()) ioc_.restart();
        auto result = asio::co_spawn(strand_, async_establish(timeout), asio::use_future);
        while (result.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
            ioc_.run_one();
        return result.get();
    }

    asio::awaitable<bool> async_establish(
        std::chrono::steady_clock::duration timeout = std::chrono::seconds(10)) {
        auto self = shared_from_this();
        co_return co_await asio::co_spawn(strand_, self->establish_serial(timeout), asio::use_awaitable);
    }

    asio::awaitable<bool> async_send_udp(std::vector<uint8_t> frame) {
        auto self = shared_from_this();
        co_return co_await asio::co_spawn(strand_, self->send_serial(std::move(frame)), asio::use_awaitable);
    }

    asio::awaitable<std::pair<size_t, asio::error_code>>
    async_recv_udp(uint8_t* buffer, size_t length) {
        auto self = shared_from_this();
        co_return co_await asio::co_spawn(strand_, self->recv_serial(buffer, length), asio::use_awaitable);
    }

    bool is_alive() const { return alive_.load(std::memory_order_acquire); }
    auto last_active() const { return last_active_.load(); }
    const udp::endpoint& relay_endpoint() const { return relay_endpoint_; }
    udp::endpoint local_udp_endpoint() const { return udp_data_.local_endpoint(); }

    void close() {
        closing_.store(true, std::memory_order_release);
        alive_.store(false, std::memory_order_release);
        if (auto self = weak_from_this().lock())
            asio::dispatch(strand_, [self] { self->close_sockets(); });
    }

private:
    asio::io_context& ioc_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::string proxy_host_;
    uint16_t proxy_port_;
    tcp::socket tcp_control_;
    udp::socket udp_data_;
    udp::endpoint relay_endpoint_;
    std::atomic<bool> alive_{false};
    std::atomic<bool> closing_{false};
    std::atomic<std::chrono::steady_clock::time_point> last_active_{std::chrono::steady_clock::now()};

    void close_sockets() {
        alive_.store(false, std::memory_order_release);
        asio::error_code ec;
        tcp_control_.close(ec);
        udp_data_.close(ec);
    }

    asio::awaitable<void> setup() {
        if (closing_) throw asio::system_error(asio::error::operation_aborted);
        tcp::resolver resolver(strand_);
        auto endpoints = co_await resolver.async_resolve(
            proxy_host_, std::to_string(proxy_port_), asio::use_awaitable);
        if (closing_) throw asio::system_error(asio::error::operation_aborted);
        co_await asio::async_connect(tcp_control_, endpoints, asio::use_awaitable);
        enable_tcp_keepalive(tcp_control_);

        std::array<uint8_t, 3> greeting{5, 1, 0};
        co_await asio::async_write(tcp_control_, asio::buffer(greeting), asio::use_awaitable);
        std::array<uint8_t, 2> auth{};
        co_await asio::async_read(tcp_control_, asio::buffer(auth), asio::use_awaitable);
        if (auth != std::array<uint8_t, 2>{5, 0})
            throw std::runtime_error("SOCKS5 UDP auth rejected");

        std::array<uint8_t, 10> request{5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(tcp_control_, asio::buffer(request), asio::use_awaitable);
        std::array<uint8_t, 4> header{};
        co_await asio::async_read(tcp_control_, asio::buffer(header), asio::use_awaitable);
        if (header[0] != 5 || header[1] != 0 || header[2] != 0)
            throw std::runtime_error("SOCKS5 UDP ASSOCIATE rejected or malformed");

        asio::ip::address address;
        uint16_t port;
        if (header[3] == 1) {
            std::array<uint8_t, 6> bound{};
            co_await asio::async_read(tcp_control_, asio::buffer(bound), asio::use_awaitable);
            address = asio::ip::address_v4({bound[0], bound[1], bound[2], bound[3]});
            port = (static_cast<uint16_t>(bound[4]) << 8) | bound[5];
        } else if (header[3] == 4) {
            std::array<uint8_t, 18> bound{};
            co_await asio::async_read(tcp_control_, asio::buffer(bound), asio::use_awaitable);
            asio::ip::address_v6::bytes_type bytes{};
            std::copy_n(bound.begin(), 16, bytes.begin());
            address = asio::ip::address_v6(bytes);
            port = (static_cast<uint16_t>(bound[16]) << 8) | bound[17];
        } else if (header[3] == 3) {
            uint8_t length{};
            co_await asio::async_read(tcp_control_, asio::buffer(&length, 1), asio::use_awaitable);
            if (!length) throw std::runtime_error("SOCKS5 UDP empty relay domain");
            std::vector<uint8_t> bound(static_cast<size_t>(length) + 2);
            co_await asio::async_read(tcp_control_, asio::buffer(bound), asio::use_awaitable);
            port = (static_cast<uint16_t>(bound[length]) << 8) | bound[length + 1];
            udp::resolver udp_resolver(strand_);
            auto relays = co_await udp_resolver.async_resolve(
                std::string(bound.begin(), bound.begin() + length), std::to_string(port), asio::use_awaitable);
            address = relays.begin()->endpoint().address();
            // Prefer the control connection's family for dual-stack names,
            // while retaining support for a relay with a different family.
            for (const auto& relay : relays) {
                if (relay.endpoint().address().is_v4() == tcp_control_.remote_endpoint().address().is_v4()) {
                    address = relay.endpoint().address();
                    break;
                }
            }
        } else {
            throw std::runtime_error("SOCKS5 UDP unsupported relay address type");
        }
        if (address.is_unspecified()) address = tcp_control_.remote_endpoint().address();
        if (!port) throw std::runtime_error("SOCKS5 UDP zero relay port");
        if (closing_) throw asio::system_error(asio::error::operation_aborted);
        relay_endpoint_ = udp::endpoint(address, port);
        auto protocol = address.is_v4() ? udp::v4() : udp::v6();
        udp_data_.open(protocol);
        udp_data_.bind(udp::endpoint(protocol, 0));
    }

    asio::awaitable<bool> establish_serial(std::chrono::steady_clock::duration timeout) {
        try {
            co_await with_setup_deadline(setup(), timeout);
            if (closing_) { close_sockets(); co_return false; }
            last_active_ = std::chrono::steady_clock::now();
            alive_.store(true, std::memory_order_release);
            PC_LOG_INFO("[SOCKS5-UDP] Session established: relay={}:{}",
                        relay_endpoint_.address().to_string(), relay_endpoint_.port());
            asio::co_spawn(strand_, watch_control(shared_from_this()), asio::detached);
            co_return true;
        } catch (const std::exception& e) {
            PC_LOG_WARN("[SOCKS5-UDP] Establish failed: {}", e.what());
            close_sockets();
            co_return false;
        }
    }

    static asio::awaitable<void> watch_control(std::shared_ptr<Socks5UdpSession> self) {
        std::array<uint8_t, 64> ignored{};
        while (self->is_alive()) {
            auto [ec, n] = co_await self->tcp_control_.async_read_some(
                asio::buffer(ignored), asio::as_tuple(asio::use_awaitable));
            (void)n;
            if (ec) {
                if (self->is_alive())
                    PC_LOG_WARN("[SOCKS5-UDP] TCP control connection lost: {}", ec.message());
                self->close_sockets();
                break;
            }
        }
    }

    asio::awaitable<bool> send_serial(std::vector<uint8_t> frame) {
        if (!is_alive()) co_return false;
        auto [ec, n] = co_await udp_data_.async_send_to(asio::buffer(frame), relay_endpoint_,
                                                     asio::as_tuple(asio::use_awaitable));
        (void)n;
        if (!ec) last_active_ = std::chrono::steady_clock::now();
        else {
            if (is_alive()) PC_LOG_WARN("[SOCKS5-UDP] Send failed: {}", ec.message());
            close_sockets();
        }
        co_return !ec;
    }

    asio::awaitable<std::pair<size_t, asio::error_code>> recv_serial(uint8_t* buffer, size_t length) {
        while (is_alive()) {
            udp::endpoint from;
            auto [ec, n] = co_await udp_data_.async_receive_from(asio::buffer(buffer, length), from,
                                                              asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (is_alive()) PC_LOG_WARN("[SOCKS5-UDP] Receive failed: {}", ec.message());
                close_sockets();
                co_return std::pair{n, ec};
            }
            if (from != relay_endpoint_) continue;
            last_active_ = std::chrono::steady_clock::now();
            co_return std::pair{n, ec};
        }
        co_return std::pair<size_t, asio::error_code>{0, asio::error::operation_aborted};
    }
};
} // namespace clew
