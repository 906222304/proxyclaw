#include "proxy/proxy_probe.hpp"

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#include <asio.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <exception>
#include <random>

namespace clew::probe {

namespace {

using clock = std::chrono::steady_clock;
using asio::ip::tcp;

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

void put16(std::vector<std::uint8_t>& v, std::size_t value) {
    v.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

// Back-patches a 16-bit length at `at` covering everything after it.
void patch16(std::vector<std::uint8_t>& v, std::size_t at) {
    const std::size_t len = v.size() - at - 2;
    v[at]     = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    v[at + 1] = static_cast<std::uint8_t>(len & 0xFF);
}

struct failure : std::exception {
    std::string why;
    explicit failure(std::string w) : why(std::move(w)) {}
    const char* what() const noexcept override { return why.c_str(); }
};

class session {
public:
    session(asio::io_context& ioc, const std::string& host, std::uint16_t port,
            const target& t, std::chrono::milliseconds budget)
        : ioc_(ioc), resolver_(ioc), socket_(ioc), deadline_(ioc),
          proxy_host_(host), proxy_port_(port), target_(t), budget_(budget) {}

    result go() {
        start_ = clock::now();
        mark_  = start_;
        deadline_.expires_after(budget_);
        deadline_.async_wait([this](const asio::error_code& ec) {
            if (ec) return;
            timed_out_ = true;
            resolver_.cancel();
            asio::error_code ignored;
            socket_.close(ignored);
        });
        asio::co_spawn(ioc_, steps(), [this](std::exception_ptr e) {
            if (e) {
                try { std::rethrow_exception(e); }
                catch (const failure& f) { fail(f.why); }
                catch (const asio::system_error& se) {
                    fail(timed_out_ ? std::string("timed out") : se.code().message());
                }
                catch (const std::exception& ex) { fail(ex.what()); }
            }
            deadline_.cancel();
            asio::error_code ignored;
            socket_.close(ignored);
        });
        ioc_.run();
        out_.total_ms = elapsed(start_);
        if (out_.ok) out_.failed_stage.clear();
        return out_;
    }

private:
    asio::io_context& ioc_;
    tcp::resolver     resolver_;
    tcp::socket       socket_;
    asio::steady_timer deadline_;
    std::string       proxy_host_;
    std::uint16_t     proxy_port_;
    target            target_;
    std::chrono::milliseconds budget_;
    bool              timed_out_{false};
    clock::time_point start_, mark_;
    std::string       current_ = "resolve";
    result            out_;

    static std::int64_t elapsed(clock::time_point since) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - since).count();
    }

    void done(const char* next) {
        out_.stages.push_back({current_, elapsed(mark_)});
        mark_    = clock::now();
        current_ = next;
    }

    void fail(std::string why) {
        out_.ok           = false;
        out_.failed_stage = current_;
        out_.error        = std::move(why);
    }

    asio::awaitable<void> read_exact(void* data, std::size_t n) {
        co_await asio::async_read(socket_, asio::buffer(data, n), asio::use_awaitable);
    }

    asio::awaitable<void> steps() {
        // resolve
        auto endpoints = co_await resolver_.async_resolve(
            proxy_host_, std::to_string(proxy_port_), asio::use_awaitable);
        done("connect");

        // connect
        co_await asio::async_connect(socket_, endpoints, asio::use_awaitable);
        socket_.set_option(tcp::no_delay(true));
        done("handshake");

        // SOCKS5 greeting, no authentication
        const std::array<std::uint8_t, 3> greeting{0x05, 0x01, 0x00};
        co_await asio::async_write(socket_, asio::buffer(greeting), asio::use_awaitable);
        std::array<std::uint8_t, 2> method{};
        co_await read_exact(method.data(), method.size());
        if (method[0] != 0x05) throw failure("not a SOCKS5 server");
        if (method[1] == 0xFF) throw failure("proxy requires authentication");
        if (method[1] != 0x00) throw failure("proxy chose an unsupported auth method");
        done("remote");

        // SOCKS5 CONNECT to the target
        std::vector<std::uint8_t> req{0x05, 0x01, 0x00};
        asio::error_code addr_ec;
        const auto literal = asio::ip::make_address(target_.host, addr_ec);
        if (!addr_ec && literal.is_v4()) {
            req.push_back(0x01);
            const auto b = literal.to_v4().to_bytes();
            req.insert(req.end(), b.begin(), b.end());
        } else if (!addr_ec && literal.is_v6()) {
            req.push_back(0x04);
            const auto b = literal.to_v6().to_bytes();
            req.insert(req.end(), b.begin(), b.end());
        } else {
            if (target_.host.size() > 255) throw failure("target host name too long");
            req.push_back(0x03);
            req.push_back(static_cast<std::uint8_t>(target_.host.size()));
            req.insert(req.end(), target_.host.begin(), target_.host.end());
        }
        put16(req, target_.port);
        co_await asio::async_write(socket_, asio::buffer(req), asio::use_awaitable);

        std::array<std::uint8_t, 4> head{};
        co_await read_exact(head.data(), head.size());
        if (head[0] != 0x05) throw failure("malformed SOCKS5 reply");
        if (head[1] != 0x00) throw failure(socks5_reply_text(head[1]));
        // Read the whole bound address so the next bytes are the target's.
        std::size_t rest = 0;
        if (head[3] == 0x01) rest = 4 + 2;
        else if (head[3] == 0x04) rest = 16 + 2;
        else if (head[3] == 0x03) {
            std::uint8_t len = 0;
            co_await read_exact(&len, 1);
            rest = std::size_t{len} + 2;
        } else throw failure("malformed SOCKS5 reply address");
        std::array<std::uint8_t, 258> bound{};
        co_await read_exact(bound.data(), rest);

        if (target_.scheme != "http" && target_.scheme != "https") {
            done("");
            out_.ok     = true;
            out_.detail = "connected";
            co_return;
        }
        done("first_byte");

        // first byte from the target
        std::vector<std::uint8_t> hello;
        if (target_.scheme == "http") {
            const std::string host_header =
                (target_.host.find(':') != std::string::npos ? "[" + target_.host + "]" : target_.host) +
                (target_.port == 80 ? std::string{} : ":" + std::to_string(target_.port));
            const std::string head_req = "HEAD " + target_.path + " HTTP/1.1\r\nHost: " + host_header +
                                         "\r\nUser-Agent: proxyclaw-probe\r\nConnection: close\r\n\r\n";
            hello.assign(head_req.begin(), head_req.end());
        } else {
            hello = build_client_hello(addr_ec ? std::string_view(target_.host) : std::string_view{});
        }
        co_await asio::async_write(socket_, asio::buffer(hello), asio::use_awaitable);

        std::array<char, 64> reply{};
        const std::size_t n = co_await socket_.async_read_some(asio::buffer(reply), asio::use_awaitable);
        const std::string_view got(reply.data(), n);
        if (target_.scheme == "http") {
            if (!got.starts_with("HTTP/")) throw failure("target reply is not HTTP");
            const auto sp = got.find(' ');
            out_.detail = (sp != std::string_view::npos && got.size() >= sp + 4)
                              ? "HTTP " + std::string(got.substr(sp + 1, 3))
                              : std::string("HTTP");
        } else {
            const auto first = static_cast<std::uint8_t>(got[0]);
            if (first == 0x16) out_.detail = "TLS handshake";
            else if (first == 0x15) out_.detail = "TLS alert";  // the target answered; the proxy works
            else throw failure("target reply is not TLS");
        }
        done("");
        out_.ok = true;
    }
};

} // namespace

std::optional<target> parse_test_url(std::string_view url) {
    target t;
    while (!url.empty() && std::isspace(static_cast<unsigned char>(url.front()))) url.remove_prefix(1);
    while (!url.empty() && std::isspace(static_cast<unsigned char>(url.back()))) url.remove_suffix(1);

    if (const auto pos = url.find("://"); pos != std::string_view::npos) {
        t.scheme = lower(url.substr(0, pos));
        url.remove_prefix(pos + 3);
    } else {
        t.scheme = "http";
    }
    std::string_view authority = url;
    t.path = "/";
    if (const auto slash = url.find_first_of("/?#"); slash != std::string_view::npos) {
        authority = url.substr(0, slash);
        auto path = url.substr(slash);
        if (const auto hash = path.find('#'); hash != std::string_view::npos) path = path.substr(0, hash);
        t.path = path.starts_with('/') ? std::string(path) : "/" + std::string(path);
        if (t.path.empty()) t.path = "/";
    }
    if (const auto at = authority.rfind('@'); at != std::string_view::npos) authority.remove_prefix(at + 1);

    std::string_view port_text;
    if (authority.starts_with('[')) {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        t.host = std::string(authority.substr(1, close - 1));
        const auto after = authority.substr(close + 1);
        if (!after.empty()) {
            if (!after.starts_with(':')) return std::nullopt;
            port_text = after.substr(1);
        }
    } else if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        t.host    = std::string(authority.substr(0, colon));
        port_text = authority.substr(colon + 1);
    } else {
        t.host = std::string(authority);
    }
    if (t.host.empty()) return std::nullopt;
    t.host = lower(t.host);

    if (!port_text.empty()) {
        unsigned value = 0;
        const auto [p, ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), value);
        if (ec != std::errc{} || p != port_text.data() + port_text.size() || value == 0 || value > 65535)
            return std::nullopt;
        t.port = static_cast<std::uint16_t>(value);
    } else if (t.scheme == "https") {
        t.port = 443;
    } else if (t.scheme == "http") {
        t.port = 80;
    } else {
        return std::nullopt;  // unknown scheme needs an explicit port
    }
    return t;
}

std::string socks5_reply_text(std::uint8_t rep) {
    switch (rep) {
        case 0x01: return "proxy: general failure";
        case 0x02: return "proxy: connection not allowed by ruleset";
        case 0x03: return "proxy: network unreachable";
        case 0x04: return "proxy: host unreachable";
        case 0x05: return "proxy: connection refused by target";
        case 0x06: return "proxy: TTL expired";
        case 0x07: return "proxy: command not supported";
        case 0x08: return "proxy: address type not supported";
        default:   return "proxy: error " + std::to_string(rep);
    }
}

// A TLS 1.2 ClientHello with SNI. Enough for a server to answer with a
// ServerHello (or an alert); the probe never completes the handshake.
std::vector<std::uint8_t> build_client_hello(std::string_view sni) {
    std::random_device rd;
    std::vector<std::uint8_t> v{0x16, 0x03, 0x01, 0x00, 0x00};  // record header, length patched
    v.push_back(0x01);                                          // ClientHello
    v.insert(v.end(), {0x00, 0x00, 0x00});                      // handshake length, patched
    const std::size_t hs_body = v.size();
    v.insert(v.end(), {0x03, 0x03});                            // TLS 1.2
    for (int i = 0; i < 32; ++i) v.push_back(static_cast<std::uint8_t>(rd()));  // random
    v.push_back(32);                                            // session id (middlebox friendly)
    for (int i = 0; i < 32; ++i) v.push_back(static_cast<std::uint8_t>(rd()));
    const std::uint16_t suites[] = {0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C, 0x009D};
    put16(v, sizeof(suites));
    for (auto s : suites) put16(v, s);
    v.insert(v.end(), {0x01, 0x00});                            // compression: null

    const std::size_t ext_len_at = v.size();
    v.insert(v.end(), {0x00, 0x00});
    if (!sni.empty() && sni.size() <= 255) {
        put16(v, 0x0000);
        put16(v, sni.size() + 5);
        put16(v, sni.size() + 3);
        v.push_back(0x00);                                      // host_name
        put16(v, sni.size());
        v.insert(v.end(), sni.begin(), sni.end());
    }
    v.insert(v.end(), {0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18});  // groups
    v.insert(v.end(), {0x00, 0x0B, 0x00, 0x02, 0x01, 0x00});                                      // point formats
    v.insert(v.end(), {0x00, 0x0D, 0x00, 0x12, 0x00, 0x10,                                        // sig algs
                       0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
                       0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01});
    v.insert(v.end(), {0x00, 0x17, 0x00, 0x00});                                                  // EMS
    v.insert(v.end(), {0xFF, 0x01, 0x00, 0x01, 0x00});                                            // reneg info
    patch16(v, ext_len_at);

    const std::size_t hs_len = v.size() - hs_body;
    v[6] = static_cast<std::uint8_t>((hs_len >> 16) & 0xFF);
    v[7] = static_cast<std::uint8_t>((hs_len >> 8) & 0xFF);
    v[8] = static_cast<std::uint8_t>(hs_len & 0xFF);
    patch16(v, 3);
    return v;
}

result run(const std::string& proxy_host, std::uint16_t proxy_port, const target& t,
           std::chrono::milliseconds budget) {
    asio::io_context ioc(1);
    session s(ioc, proxy_host, proxy_port, t, budget);
    return s.go();
}

} // namespace clew::probe
