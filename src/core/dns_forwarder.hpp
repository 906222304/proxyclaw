#pragma once

// Local UDP DNS -> SOCKS5 UDP, with bounded TCP fallback through the same proxy.
#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "core/dns_wire.hpp"
#include "core/log.hpp"
#include "udp/socks5_udp_session.hpp"
#include "udp/socks5_udp_codec.hpp"

namespace clew {
class dns_forwarder {
    using tcp = asio::ip::tcp;
    using udp = asio::ip::udp;
    using clock = std::chrono::steady_clock;
    struct pending_query {
        uint16_t upstream_id, client_id;
        udp::endpoint client;
        std::vector<uint8_t> packet;
        asio::steady_timer deadline;
        tcp::socket socket;
        tcp::resolver resolver;
        bool tcp_started = false, done = false;
        pending_query(asio::io_context& ioc, uint16_t id, const udp::endpoint& ep,
                      std::span<const uint8_t> input)
            : upstream_id(id), client_id(dns_wire::u16(input.data())), client(ep),
              packet(input.begin(), input.end()), deadline(ioc), socket(ioc), resolver(ioc) {
            dns_wire::set_id(packet, id);
        }
        void cancel() {
            deadline.cancel();
            resolver.cancel();
            asio::error_code ec;
            socket.close(ec);
        }
    };

    // Serialize sockets/timers on one executor. stop() joins it before the
    // manager releases this object, even before the app's io_context starts.
    struct state {
        asio::io_context ioc;
        udp::endpoint listen_ep;
        udp::socket listener{ioc};
        std::shared_ptr<Socks5UdpSession> session;
        std::string proxy_host;
        uint16_t proxy_port;
        uint32_t dns_ip_net;
        uint16_t dns_port;
        std::chrono::milliseconds udp_timeout, tcp_timeout;
        bool running = false;
        std::random_device random;
        size_t tcp_active = 0;
        static constexpr size_t max_pending = 1024, max_tcp = 64;
        std::unordered_map<uint16_t, std::shared_ptr<pending_query>> pending;
        // Quarantine released IDs so late UDP replies cannot hit a new query.
        std::array<clock::time_point, 65536> reusable_after{};
        state(const std::string& ip, uint16_t port, const std::string& proxy, uint16_t pp,
              const std::string& dns, uint16_t dp, std::chrono::milliseconds ut,
              std::chrono::milliseconds tt)
            : listen_ep(asio::ip::make_address(ip), port), proxy_host(proxy), proxy_port(pp),
              dns_ip_net(htonl(asio::ip::make_address_v4(dns).to_uint())), dns_port(dp),
              udp_timeout(ut), tcp_timeout(tt) {}
        void shutdown() {
            running = false;
            asio::error_code ec;
            listener.close(ec);
            if (session)
                session->close();
            for (auto& [id, q] : pending) {
                (void)id;
                q->done = true;
                q->cancel();
            }
            pending.clear();
        }
        std::optional<uint16_t> allocate_id() {
            auto now = clock::now();
            // Keep the rewritten DNS IDs unpredictable; scan from a random
            // starting point to keep allocation bounded when IDs are occupied.
            uint16_t first = static_cast<uint16_t>(random());
            for (size_t i = 0; i < 65536; ++i) {
                uint16_t id = static_cast<uint16_t>(first + i);
                if (!pending.contains(id) && reusable_after[id] <= now)
                    return id;
            }
            return std::nullopt;
        }
        void send_reply(const udp::endpoint& ep, std::vector<uint8_t> packet) {
            if (!running || packet.empty())
                return;
            auto data = std::make_shared<std::vector<uint8_t>>(std::move(packet));
            listener.async_send_to(asio::buffer(*data), ep, [data](asio::error_code ec, size_t) {
                if (ec && ec != asio::error::operation_aborted)
                    PC_LOG_DEBUG("[DNS-FWD] Client reply failed: {}", ec.message());
            });
        }
        void finish(const std::shared_ptr<pending_query>& q, std::vector<uint8_t> response) {
            if (q->done)
                return;
            q->done = true;
            q->cancel();
            pending.erase(q->upstream_id);
            reusable_after[q->upstream_id] = clock::now() + std::chrono::seconds(10);
            if (response.size() > dns_wire::udp_limit(q->packet))
                response = dns_wire::empty_response(q->packet, response[3] & 0x0f, true);
            if (!response.empty())
                dns_wire::set_id(response, q->client_id);
            send_reply(q->client, std::move(response));
        }
        void fail(const std::shared_ptr<pending_query>& q) {
            finish(q, dns_wire::empty_response(q->packet, 2));
        }
        void begin_tcp(const std::shared_ptr<pending_query>& q) {
            if (!running || q->done || q->tcp_started)
                return;
            if (tcp_active >= max_tcp) {
                fail(q);
                return;
            }
            q->tcp_started = true;
            ++tcp_active;
            PC_LOG_DEBUG("[DNS-FWD] TCP fallback tx={:#06x}", q->upstream_id);
            q->deadline.expires_after(tcp_timeout);
            q->deadline.async_wait([this, q](asio::error_code ec) {
                if (!ec && !q->done) {
                    PC_LOG_WARN("[DNS-FWD] TCP fallback timed out tx={:#06x}", q->upstream_id);
                    fail(q); // Cancels resolve/connect/handshake/read/write too.
                }
            });
            asio::co_spawn(ioc, tcp_query(q), [this, q](std::exception_ptr error) {
                --tcp_active;
                if (error && !q->done) {
                    try {
                        std::rethrow_exception(error);
                    } catch (const std::exception& e) {
                        PC_LOG_WARN("[DNS-FWD] TCP fallback failed tx={:#06x}: {}", q->upstream_id,
                                    e.what());
                    }
                    fail(q);
                }
            });
        }
        // Consume the whole variable-length SOCKS5 reply (RFC 1928), including
        // domain/IPv6 BND.ADDR, before reading the DNS TCP length prefix.
        asio::awaitable<void> connect_tunnel(const std::shared_ptr<pending_query>& q) {
            auto eps = co_await q->resolver.async_resolve(proxy_host, std::to_string(proxy_port),
                                                          asio::use_awaitable);
            if (q->done)
                co_return;
            co_await asio::async_connect(q->socket, eps, asio::use_awaitable);
            std::array<uint8_t, 3> greeting{5, 1, 0};
            co_await asio::async_write(q->socket, asio::buffer(greeting), asio::use_awaitable);
            std::array<uint8_t, 2> auth{};
            co_await asio::async_read(q->socket, asio::buffer(auth), asio::use_awaitable);
            if (auth[0] != 5 || auth[1] != 0)
                throw std::runtime_error("SOCKS5 authentication rejected");
            std::array<uint8_t, 10> request{5, 1, 0, 1};
            std::memcpy(request.data() + 4, &dns_ip_net, 4);
            request[8] = static_cast<uint8_t>(dns_port >> 8);
            request[9] = static_cast<uint8_t>(dns_port);
            co_await asio::async_write(q->socket, asio::buffer(request), asio::use_awaitable);
            std::array<uint8_t, 4> reply{};
            co_await asio::async_read(q->socket, asio::buffer(reply), asio::use_awaitable);
            if (reply[0] != 5 || reply[1] != 0 || reply[2] != 0)
                throw std::runtime_error("SOCKS5 CONNECT rejected");
            size_t remainder;
            if (reply[3] == 1)
                remainder = 6;
            else if (reply[3] == 4)
                remainder = 18;
            else if (reply[3] == 3) {
                std::array<uint8_t, 1> length{};
                co_await asio::async_read(q->socket, asio::buffer(length), asio::use_awaitable);
                if (!length[0])
                    throw std::runtime_error("empty SOCKS5 bound address");
                remainder = size_t(length[0]) + 2;
            } else
                throw std::runtime_error("invalid SOCKS5 address type");
            std::vector<uint8_t> bound(remainder);
            co_await asio::async_read(q->socket, asio::buffer(bound), asio::use_awaitable);
        }
        asio::awaitable<void> tcp_query(std::shared_ptr<pending_query> q) {
            if (q->done)
                co_return;
            co_await connect_tunnel(q);
            if (q->done)
                co_return;
            // DNS over TCP has a two-byte big-endian payload length (RFC 7766).
            std::vector<uint8_t> framed(q->packet.size() + 2);
            framed[0] = static_cast<uint8_t>(q->packet.size() >> 8);
            framed[1] = static_cast<uint8_t>(q->packet.size());
            std::copy(q->packet.begin(), q->packet.end(), framed.begin() + 2);
            co_await asio::async_write(q->socket, asio::buffer(framed), asio::use_awaitable);
            std::array<uint8_t, 2> length{};
            co_await asio::async_read(q->socket, asio::buffer(length), asio::use_awaitable);
            auto size = dns_wire::u16(length.data());
            if (size < 12)
                throw std::runtime_error("short TCP DNS reply");
            std::vector<uint8_t> response(size);
            co_await asio::async_read(q->socket, asio::buffer(response), asio::use_awaitable);
            if (q->done)
                co_return;
            if (!dns_wire::matches(response, q->packet) || (response[2] & 2))
                throw std::runtime_error("invalid TCP DNS reply");
            finish(q, std::move(response));
        }
        asio::awaitable<void> query_loop() {
            std::array<uint8_t, 65535> buf{};
            while (running) {
                udp::endpoint client;
                auto [ec, n] = co_await listener.async_receive_from(
                    asio::buffer(buf), client, asio::as_tuple(asio::use_awaitable));
                if (ec) {
                    if (ec == asio::error::connection_reset ||
                        ec == asio::error::connection_refused)
                        continue;
                    break;
                }
                std::span<const uint8_t> query(buf.data(), n);
                if (n < 12 || n > 65507 || (buf[2] & 0x80) || !dns_wire::parse_questions(query))
                    continue;
                auto id = pending.size() < max_pending ? allocate_id() : std::nullopt;
                if (!id) {
                    send_reply(client, dns_wire::empty_response(query, 2));
                    continue;
                }
                auto q = std::make_shared<pending_query>(ioc, *id, client, query);
                pending.emplace(*id, q);
                q->deadline.expires_after(udp_timeout);
                q->deadline.async_wait([this, q](asio::error_code error) {
                    if (!error)
                        begin_tcp(q);
                });
                if (!session->is_alive()) {
                    begin_tcp(q);
                    continue;
                }
                auto frame =
                    socks5_udp::encode(dns_ip_net, dns_port, q->packet.data(), q->packet.size());
                if (!co_await session->async_send_udp(std::move(frame)))
                    begin_tcp(q);
            }
        }
        asio::awaitable<void> response_loop() {
            std::array<uint8_t, 65535> buf{};
            auto source = session;
            while (running) {
                auto [n, ec] = co_await source->async_recv_udp(buf.data(), buf.size());
                if (ec) {
                    if (ec == asio::error::connection_reset ||
                        ec == asio::error::connection_refused)
                        continue;
                    break;
                }
                auto frame = socks5_udp::decode(buf.data(), n);
                if (!frame || frame->addr_net != dns_ip_net || frame->port_host != dns_port ||
                    frame->data_len < 12)
                    continue;
                auto it = pending.find(dns_wire::u16(frame->data));
                if (it == pending.end())
                    continue;
                auto q = it->second; // Own it before finish() erases the map entry.
                std::span<const uint8_t> response(frame->data, frame->data_len);
                if (!dns_wire::matches(response, q->packet))
                    continue;
                if (response[2] & 2) {
                    begin_tcp(q);
                    continue;
                }
                // A valid late UDP response can win and cancel the TCP attempt.
                finish(q, {response.begin(), response.end()});
            }
        }
    };
    std::shared_ptr<state> state_;
    std::thread worker_;

  public:
    dns_forwarder(asio::io_context& /*application_ioc*/, const std::string& listen_ip,
                  uint16_t listen_port, const std::string& proxy_host, uint16_t proxy_port,
                  const std::string& dns_server = "8.8.8.8", uint16_t dns_port = 53,
                  std::chrono::milliseconds udp_timeout = std::chrono::milliseconds(1500),
                  std::chrono::milliseconds tcp_timeout = std::chrono::milliseconds(3000))
        : state_(std::make_shared<state>(listen_ip, listen_port, proxy_host, proxy_port, dns_server,
                                         dns_port, udp_timeout, tcp_timeout)) {
        if (udp_timeout.count() <= 0 || tcp_timeout.count() <= 0)
            throw std::invalid_argument("DNS timeouts must be positive");
    }
    ~dns_forwarder() { stop(); }
    dns_forwarder(const dns_forwarder&) = delete;
    dns_forwarder& operator=(const dns_forwarder&) = delete;
    bool start() {
        if (worker_.joinable())
            return true;
        try {
            state_->ioc.restart();
            state_->listener.open(udp::v4());
            state_->listener.bind(state_->listen_ep);
            state_->session = std::make_shared<Socks5UdpSession>(state_->ioc, state_->proxy_host,
                                                                 state_->proxy_port);
            if (!state_->session->establish()) {
                state_->shutdown();
                return false;
            }
            state_->running = true;
            auto report_loop_error = [](std::exception_ptr error) {
                if (!error)
                    return;
                try {
                    std::rethrow_exception(error);
                } catch (const std::exception& e) {
                    PC_LOG_ERROR("[DNS-FWD] Receive loop failed: {}", e.what());
                }
            };
            asio::co_spawn(state_->ioc, state_->query_loop(), report_loop_error);
            asio::co_spawn(state_->ioc, state_->response_loop(), report_loop_error);
            worker_ = std::thread([s = state_] { s->ioc.run(); });
            PC_LOG_INFO("[DNS-FWD] UDP timeout={}ms, TCP fallback timeout={}ms",
                        state_->udp_timeout.count(), state_->tcp_timeout.count());
            return true;
        } catch (const std::exception& e) {
            PC_LOG_ERROR("[DNS-FWD] Start failed: {}", e.what());
            state_->shutdown();
            return false;
        }
    }
    void stop() {
        if (worker_.joinable()) {
            asio::post(state_->ioc, [s = state_] { s->shutdown(); });
            worker_.join();
        }
        // Also cover a worker that returned after an unexpected receive error.
        // No I/O thread remains here, so synchronous cleanup/draining is safe.
        state_->shutdown();
        state_->ioc.restart();
        state_->ioc.poll();
    }
};
} // namespace clew
