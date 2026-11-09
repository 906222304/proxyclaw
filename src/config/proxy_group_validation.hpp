#pragma once

// Proxy group input validation and host normalisation.
//
// Only SOCKS5 without authentication is implemented (proxy/socks5_async.hpp),
// so a group is accepted only when it can actually be used:
//   host      non-empty after trimming; "[v6]" brackets are stripped so the
//             stored value is what the resolver takes (relay, UDP session and
//             speed test all resolve the same string); "host:port" is
//             rejected (the port has its own field)
//   port      an integer 1..65535 (never truncated, never defaulted when
//             present but invalid)
//   type      "socks5" (case-insensitive); anything else, e.g. "http", is
//             rejected as unsupported
//   user / username / password
//             must be absent or empty: SOCKS5 authentication is not
//             implemented, and accepting credentials that are never sent
//             would fail every connection silently
//
// Pure (no Windows, no config types) so the unit tests and the API share it.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "config/proxy_host.hpp"

namespace clew {

struct proxy_group_input {
    std::optional<std::string>   name;
    std::optional<std::string>   host;      // normalised
    std::optional<std::uint16_t> port;
    std::optional<std::string>   type;      // lower-cased, always "socks5"
    std::optional<std::string>   test_url;
};

struct proxy_group_error {
    std::string field;
    std::string message;
};

// Parse the fields present in `body` (a create body or a PATCH-style update).
// Absent fields stay nullopt. Returns the first problem found, if any.
inline std::optional<proxy_group_error> parse_proxy_group_input(const nlohmann::json& body,
                                                                proxy_group_input& out) {
    if (!body.is_object()) return proxy_group_error{"", "request body must be a JSON object"};

    auto string_field = [&body](const char* key, std::optional<std::string>& dst)
        -> std::optional<proxy_group_error> {
        auto it = body.find(key);
        if (it == body.end()) return std::nullopt;
        if (!it->is_string()) return proxy_group_error{key, std::string(key) + " must be a string"};
        dst = it->get<std::string>();
        return std::nullopt;
    };

    if (auto e = string_field("name", out.name)) return e;
    if (auto e = string_field("test_url", out.test_url)) return e;

    if (auto e = string_field("host", out.host)) return e;
    if (out.host) {
        *out.host = normalize_proxy_host(*out.host);
        const auto& h = *out.host;
        if (h.empty()) return proxy_group_error{"host", "host must not be empty"};
        for (char c : h) {
            if (std::isspace(static_cast<unsigned char>(c)) || c == '/' || c == '[' || c == ']') {
                return proxy_group_error{"host", "host must be a hostname or an IP address"};
            }
        }
        // Exactly one ':' is "host:port"; an IPv6 literal has at least two.
        const auto colons = static_cast<std::size_t>(std::count(h.begin(), h.end(), ':'));
        if (colons == 1) {
            return proxy_group_error{"host", "host must not include a port; use the port field"};
        }
    }

    if (auto it = body.find("port"); it != body.end()) {
        const bool integral = it->is_number_integer() || it->is_number_unsigned();
        const bool in_range = integral && (it->is_number_unsigned()
            ? it->get<std::uint64_t>() >= 1 && it->get<std::uint64_t>() <= 65535
            : it->get<std::int64_t>() >= 1 && it->get<std::int64_t>() <= 65535);
        if (!in_range) {
            return proxy_group_error{"port", "port must be an integer between 1 and 65535"};
        }
        out.port = static_cast<std::uint16_t>(it->get<std::int64_t>());
    }

    if (auto e = string_field("type", out.type)) return e;
    if (out.type) {
        std::string t = *out.type;
        for (auto& c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (t != "socks5") {
            return proxy_group_error{"type", "unsupported proxy type '" + *out.type +
                                                 "': only socks5 (no authentication) is supported"};
        }
        out.type = t;
    }

    for (const char* key : {"user", "username", "password"}) {
        auto it = body.find(key);
        if (it == body.end() || it->is_null()) continue;
        if (!it->is_string() || !it->get<std::string>().empty()) {
            return proxy_group_error{key, "SOCKS5 authentication is not supported; "
                                          "leave user and password empty"};
        }
    }
    return std::nullopt;
}

} // namespace clew
