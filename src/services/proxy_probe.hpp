#pragma once

// proxy_probe — staged SOCKS5 reachability test for a proxy group.
//
// Runs on its own private io_context with one overall deadline, so a dead or
// black-holed proxy costs at most `budget` and never an unbounded blocking
// connect. Accepts proxy hosts as IPv4, IPv6 or a domain name.
//
// Stages, timed separately (milliseconds since the previous stage ended):
//   resolve     resolve the proxy host
//   connect     TCP connect to the proxy
//   handshake   SOCKS5 greeting (no-auth)
//   remote      SOCKS5 CONNECT to the test target (the proxy reaching it)
//   first_byte  first byte back from the target: an HTTP status line for
//               http://, a TLS ServerHello (or alert) for https://
// For any other scheme the probe stops after `remote`.

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace clew::probe {

struct target {
    std::string   scheme;   // "http", "https", or other (lower-case)
    std::string   host;     // domain or IP literal (IPv6 without brackets)
    std::uint16_t port{};
    std::string   path;     // starts with '/'
};

// Parses a test URL. No scheme means http. Default ports: http 80, https 443.
// Returns nullopt for an empty host or an invalid port.
std::optional<target> parse_test_url(std::string_view url);

struct stage {
    std::string   name;
    std::int64_t  ms{};
};

struct result {
    bool               ok{false};
    std::vector<stage> stages;        // the stages that completed, in order
    std::string        failed_stage;  // empty when ok
    std::string        error;         // short English reason when !ok
    std::string        detail;        // e.g. "HTTP 204", "TLS handshake"
    std::int64_t       total_ms{};
};

result run(const std::string& proxy_host, std::uint16_t proxy_port, const target& t,
           std::chrono::milliseconds budget = std::chrono::milliseconds(8000));

// Exposed for tests.
std::vector<std::uint8_t> build_client_hello(std::string_view sni);
std::string               socks5_reply_text(std::uint8_t rep);

} // namespace clew::probe
