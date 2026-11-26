#pragma once

// RFC 1928 method negotiation + RFC 1929 username/password subnegotiation.
//
// Pure Asio coroutine helper (no quill, no Windows): shared across the TCP
// relay (socks5_async.hpp), UDP ASSOCIATE (socks5_udp_session.hpp), staged
// speed test (proxy_probe.cpp), and DNS forwarder (dns_forwarder.hpp).
//
// Credentials are never formatted into exception messages.

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#include <asio.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "proxy/socks5_credentials.hpp"

namespace clew {

class socks5_auth_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Negotiate SOCKS5 authentication on an already-connected TCP socket.
//
// - Without credentials: offers NO_AUTH (0x00) only.
// - With credentials: offers NO_AUTH (0x00) and USER/PASS (0x02). If the
//   server selects 0x00, no credentials are sent; if 0x02, performs RFC 1929
//   subnegotiation ([0x01][ulen][user][plen][password]) and checks [0x01, 0x00].
inline asio::awaitable<void>
socks5_negotiate_auth(asio::ip::tcp::socket& sock, const socks5_credentials& creds = {}) {
    if (creds.empty()) {
        const std::array<std::uint8_t, 3> greeting{0x05, 0x01, 0x00};
        co_await asio::async_write(sock, asio::buffer(greeting), asio::use_awaitable);
    } else {
        if (creds.user.size() > 255 || creds.password.size() > 255) {
            throw socks5_auth_error("SOCKS5 credentials exceed 255 bytes");
        }
        const std::array<std::uint8_t, 4> greeting{0x05, 0x02, 0x00, 0x02};
        co_await asio::async_write(sock, asio::buffer(greeting), asio::use_awaitable);
    }

    std::array<std::uint8_t, 2> chosen{};
    co_await asio::async_read(sock, asio::buffer(chosen), asio::use_awaitable);

    if (chosen[0] != 0x05) {
        throw socks5_auth_error("not a SOCKS5 server");
    }
    if (chosen[1] == 0x00) {
        co_return;
    }
    if (chosen[1] == 0xFF) {
        throw socks5_auth_error(creds.empty()
                                    ? "proxy requires authentication"
                                    : "proxy rejected offered authentication methods");
    }
    if (chosen[1] != 0x02) {
        throw socks5_auth_error("proxy chose an unsupported authentication method");
    }
    if (creds.empty()) {
        throw socks5_auth_error("proxy requires authentication");
    }

    // RFC 1929 section 2: VER=0x01, ULEN, UNAME, PLEN, PASSWD.
    std::vector<std::uint8_t> req;
    req.reserve(3 + creds.user.size() + creds.password.size());
    req.push_back(0x01);
    req.push_back(static_cast<std::uint8_t>(creds.user.size()));
    req.insert(req.end(), creds.user.begin(), creds.user.end());
    req.push_back(static_cast<std::uint8_t>(creds.password.size()));
    req.insert(req.end(), creds.password.begin(), creds.password.end());
    co_await asio::async_write(sock, asio::buffer(req), asio::use_awaitable);

    std::array<std::uint8_t, 2> reply{};
    co_await asio::async_read(sock, asio::buffer(reply), asio::use_awaitable);
    if (reply[0] != 0x01) {
        throw socks5_auth_error("malformed SOCKS5 authentication reply");
    }
    if (reply[1] != 0x00) {
        throw socks5_auth_error("SOCKS5 authentication failed");
    }
}

} // namespace clew
