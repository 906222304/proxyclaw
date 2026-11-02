// Staged proxy speed test (src/services/proxy_probe.*) against a local fake
// SOCKS5 server. No driver, no admin rights, no internet. Also builds and runs
// on Linux (asio only).

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "services/proxy_probe.hpp"

using asio::ip::tcp;
using namespace std::chrono_literals;
namespace probe = clew::probe;

namespace {

int failures = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { ++failures; std::cerr << "FAIL: " << what << "\n"; }
}

enum class mode { ok_http, ok_tls, need_auth, refused, silent, domain_bound };

// One-connection-at-a-time fake proxy that also plays the target.
class fake_proxy {
public:
    fake_proxy(mode m, bool v6 = false)
        : acceptor_(ioc_, tcp::endpoint(v6 ? tcp::v6() : tcp::v4(), 0)), mode_(m) {
        thread_ = std::thread([this] { serve(); });
    }
    ~fake_proxy() {
        stop_ = true;
        asio::error_code ec;
        acceptor_.close(ec);
        thread_.join();
    }
    std::uint16_t port() const { return acceptor_.local_endpoint().port(); }
    std::vector<std::uint8_t> last_request;  // SOCKS5 CONNECT as received

private:
    asio::io_context ioc_;
    tcp::acceptor acceptor_;
    mode mode_;
    std::atomic<bool> stop_{false};
    std::thread thread_;

    void serve() {
        asio::error_code ec;
        tcp::socket s(ioc_);
        acceptor_.accept(s, ec);
        if (ec) return;
        try {
            if (mode_ == mode::silent) { std::this_thread::sleep_for(1500ms); return; }
            std::uint8_t g[3];
            asio::read(s, asio::buffer(g));
            if (mode_ == mode::need_auth) {
                const std::uint8_t r[2] = {5, 0xFF};
                asio::write(s, asio::buffer(r));
                return;
            }
            const std::uint8_t r[2] = {5, 0};
            asio::write(s, asio::buffer(r));
            std::uint8_t head[5];
            asio::read(s, asio::buffer(head));
            last_request.assign(head, head + 5);
            std::size_t rest = head[3] == 1 ? 3 + 2 : head[3] == 4 ? 15 + 2 : head[4] + 2;
            std::vector<std::uint8_t> tail(rest);
            asio::read(s, asio::buffer(tail));
            last_request.insert(last_request.end(), tail.begin(), tail.end());
            if (mode_ == mode::refused) {
                const std::uint8_t rep[10] = {5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
                asio::write(s, asio::buffer(rep));
                return;
            }
            if (mode_ == mode::domain_bound) {
                // bound address as a domain, then the target bytes right after
                std::vector<std::uint8_t> rep{5, 0, 0, 3, 9};
                for (char c : std::string("relay.lan")) rep.push_back(static_cast<std::uint8_t>(c));
                rep.push_back(0x1F); rep.push_back(0x90);
                asio::write(s, asio::buffer(rep));
            } else {
                const std::uint8_t rep[10] = {5, 0, 0, 1, 127, 0, 0, 1, 0x1F, 0x90};
                asio::write(s, asio::buffer(rep));
            }
            std::array<char, 2048> req{};
            s.read_some(asio::buffer(req));
            if (mode_ == mode::ok_tls) {
                check(static_cast<std::uint8_t>(req[0]) == 0x16, "client sent a TLS record");
                const std::uint8_t sh[5] = {0x16, 3, 3, 0, 0};
                asio::write(s, asio::buffer(sh));
            } else {
                asio::write(s, asio::buffer(std::string("HTTP/1.1 204 No Content\r\n\r\n")));
            }
        } catch (...) {}
    }
};

std::vector<std::string> names(const probe::result& r) {
    std::vector<std::string> out;
    for (auto& s : r.stages) out.push_back(s.name);
    return out;
}

void url_parsing() {
    auto a = probe::parse_test_url("http://www.gstatic.com/generate_204");
    check(a && a->host == "www.gstatic.com" && a->port == 80 && a->path == "/generate_204", "http url");
    auto b = probe::parse_test_url("https://www.google.com");
    check(b && b->scheme == "https" && b->port == 443 && b->path == "/", "https default port");
    auto c = probe::parse_test_url("HTTPS://[2001:db8::1]:8443/x?y=1");
    check(c && c->host == "2001:db8::1" && c->port == 8443 && c->path == "/x?y=1", "ipv6 url with port");
    auto d = probe::parse_test_url("example.com:8080");
    check(d && d->scheme == "http" && d->port == 8080, "no scheme means http");
    check(!probe::parse_test_url("http://:80/"), "empty host rejected");
    check(!probe::parse_test_url("http://a:99999/"), "bad port rejected");
    check(!probe::parse_test_url("ftp://a/"), "unknown scheme without port rejected");
}

void client_hello_shape() {
    auto h = probe::build_client_hello("www.google.com");
    check(h.size() > 60 && h[0] == 0x16 && h[5] == 0x01, "record + ClientHello type");
    check(((h[3] << 8) | h[4]) == static_cast<int>(h.size() - 5), "record length matches");
    const std::string body(h.begin(), h.end());
    check(body.find("www.google.com") != std::string::npos, "SNI present");
}

probe::target http_target() { return *probe::parse_test_url("http://example.com/generate_204"); }

void success_http_ipv4() {
    fake_proxy p(mode::ok_http);
    auto r = probe::run("127.0.0.1", p.port(), http_target(), 3000ms);
    check(r.ok, "http probe ok: " + r.error);
    check(names(r) == std::vector<std::string>{"resolve", "connect", "handshake", "remote", "first_byte"},
          "all five stages reported");
    check(r.detail == "HTTP 204", "status parsed: " + r.detail);
    check(p.last_request.size() > 4 && p.last_request[3] == 3, "target sent as a domain");
}

void success_ipv6_and_domain_proxy() {
    {
        fake_proxy p(mode::ok_http, /*v6=*/true);
        auto r = probe::run("::1", p.port(), http_target(), 3000ms);
        check(r.ok, "IPv6 proxy ok: " + r.error);
    }
    {
        fake_proxy p(mode::ok_http);
        auto r = probe::run("localhost", p.port(), http_target(), 3000ms);
        check(r.ok, "domain proxy ok: " + r.error);
    }
}

void domain_bound_reply_is_fully_read() {
    fake_proxy p(mode::domain_bound);
    auto r = probe::run("127.0.0.1", p.port(), http_target(), 3000ms);
    check(r.ok && r.detail == "HTTP 204", "domain BND address consumed before target bytes: " + r.error);
}

void tls_target() {
    fake_proxy p(mode::ok_tls);
    auto r = probe::run("127.0.0.1", p.port(), *probe::parse_test_url("https://www.google.com"), 3000ms);
    check(r.ok && r.detail == "TLS handshake", "https probe reads a TLS record: " + r.error);
}

void failures_name_their_stage() {
    {
        fake_proxy p(mode::need_auth);
        auto r = probe::run("127.0.0.1", p.port(), http_target(), 3000ms);
        check(!r.ok && r.failed_stage == "handshake" && r.error.find("authentication") != std::string::npos,
              "auth required -> handshake: " + r.failed_stage + " " + r.error);
    }
    {
        fake_proxy p(mode::refused);
        auto r = probe::run("127.0.0.1", p.port(), http_target(), 3000ms);
        check(!r.ok && r.failed_stage == "remote" && r.error.find("refused") != std::string::npos,
              "rep=5 -> remote: " + r.failed_stage + " " + r.error);
    }
    {
        fake_proxy p(mode::silent);
        const auto t0 = std::chrono::steady_clock::now();
        auto r = probe::run("127.0.0.1", p.port(), http_target(), 400ms);
        const auto took = std::chrono::steady_clock::now() - t0;
        check(!r.ok && r.failed_stage == "handshake" && r.error == "timed out",
              "silent proxy -> handshake timeout: " + r.failed_stage + " " + r.error);
        check(took < 1200ms, "budget enforced");
    }
    {
        std::uint16_t closed;
        {
            asio::io_context ioc;
            tcp::acceptor a(ioc, tcp::endpoint(tcp::v4(), 0));
            closed = a.local_endpoint().port();
        }
        auto r = probe::run("127.0.0.1", closed, http_target(), 3000ms);
        check(!r.ok && r.failed_stage == "connect", "closed port -> connect: " + r.failed_stage + " " + r.error);
    }
    {
        auto r = probe::run("no-such-host.invalid", 1080, http_target(), 3000ms);
        check(!r.ok && (r.failed_stage == "resolve"), "bad host -> resolve: " + r.failed_stage + " " + r.error);
    }
}

} // namespace

int main() {
    url_parsing();
    client_hello_shape();
    success_http_ipv4();
    success_ipv6_and_domain_proxy();
    domain_bound_reply_is_fully_read();
    tls_target();
    failures_name_their_stage();
    if (failures) { std::cerr << failures << " check(s) failed\n"; return 1; }
    std::cout << "proxy_probe_tests: all passed\n";
    return 0;
}
