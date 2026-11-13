#pragma once

// Async SOCKS5 client handshake using C++20 coroutines.
// Replaces blocking socks5_client.hpp.
// Protocol: RFC 1928 (SOCKS5), IPv4 / IPv6 CONNECT, no auth.

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <format>
#include <stdexcept>
#include "core/log.hpp"

namespace clew {

using asio::ip::tcp;

// RFC 1928 handshake / reply violation. Inherits from std::runtime_error
// so existing catch (const std::exception&) sites (relay.hpp, async_acceptor)
// continue to work without change.
class socks5_protocol_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// SOCKS5 CONNECT destination: IPv4 (host order) or IPv6 (network order).
struct socks5_dest {
    bool ipv6 = false;
    uint32_t v4_host = 0;
    std::array<uint8_t, 16> v6{};
    uint16_t port = 0;
};

// The CONNECT request for `d` (RFC 1928 section 4).
inline std::size_t socks5_connect_request(const socks5_dest& d, std::array<uint8_t, 22>& req) {
    req[0] = 0x05;  // VER
    req[1] = 0x01;  // CMD = CONNECT
    req[2] = 0x00;  // RSV
    std::size_t n = 4;
    if (d.ipv6) {
        req[3] = 0x04;  // ATYP = IPv6
        std::memcpy(&req[4], d.v6.data(), 16);
        n += 16;
    } else {
        req[3] = 0x01;  // ATYP = IPv4
        req[4] = static_cast<uint8_t>(d.v4_host >> 24);
        req[5] = static_cast<uint8_t>(d.v4_host >> 16);
        req[6] = static_cast<uint8_t>(d.v4_host >> 8);
        req[7] = static_cast<uint8_t>(d.v4_host);
        n += 4;
    }
    req[n]     = static_cast<uint8_t>(d.port >> 8);
    req[n + 1] = static_cast<uint8_t>(d.port);
    return n + 2;
}

// SOCKS5 handshake as a coroutine.
// Establishes a SOCKS5 tunnel through `sock` to `dest`.
inline asio::awaitable<void>
socks5_handshake(tcp::socket& sock, const socks5_dest& dest)
{
    // Phase 1: Greeting — no auth
    std::array<uint8_t, 3> greeting = {0x05, 0x01, 0x00};  // VER=5, 1 method, NO_AUTH
    co_await asio::async_write(sock, asio::buffer(greeting), asio::use_awaitable);

    std::array<uint8_t, 2> greeting_reply{};
    co_await asio::async_read(sock, asio::buffer(greeting_reply), asio::use_awaitable);

    if (greeting_reply[0] != 0x05 || greeting_reply[1] != 0x00) {
        throw socks5_protocol_error("SOCKS5 greeting failed: server rejected NO_AUTH");
    }

    // Phase 2: CONNECT request
    std::array<uint8_t, 22> connect_req{};
    const auto req_len = socks5_connect_request(dest, connect_req);
    co_await asio::async_write(sock, asio::buffer(connect_req.data(), req_len), asio::use_awaitable);

    // Read the header first: a rejection may arrive without an address tail.
    std::array<uint8_t, 4> connect_reply{};
    co_await asio::async_read(sock, asio::buffer(connect_reply), asio::use_awaitable);

    if (connect_reply[0] != 0x05 || connect_reply[2] != 0x00) {
        throw socks5_protocol_error("SOCKS5 connect: invalid reply header");
    }
    if (connect_reply[1] != 0x00) {
        PC_LOG_WARN("[SOCKS5] Connect failed: reply code 0x{:02X}", connect_reply[1]);
        throw socks5_protocol_error(std::format("SOCKS5 connect: server returned error {}",
                                                 connect_reply[1]));
    }

    // Consume the entire BND endpoint, including IPv6/domain replies. Leaving
    // address bytes unread corrupts the application's first TLS response.
    std::array<uint8_t, 257> tail{};
    size_t length;
    switch (connect_reply[3]) {
    case 0x01: length = 6; break;
    case 0x04: length = 18; break;
    case 0x03:
        co_await asio::async_read(sock, asio::buffer(tail.data(), 1), asio::use_awaitable);
        if (!tail[0]) throw socks5_protocol_error("SOCKS5 connect: empty bound domain");
        length = static_cast<size_t>(tail[0]) + 2;
        break;
    default: throw socks5_protocol_error("SOCKS5 connect: unsupported address type");
    }
    co_await asio::async_read(sock, asio::buffer(tail.data(), length), asio::use_awaitable);
}

// IPv4 destination in host byte order (WinDivert SOCKET layer native).
inline asio::awaitable<void>
socks5_handshake(tcp::socket& sock, uint32_t dest_ip_host, uint16_t dest_port)
{
    socks5_dest d;
    d.v4_host = dest_ip_host;
    d.port = dest_port;
    co_await socks5_handshake(sock, d);
}

} // namespace clew
