#pragma once

// Request gate for the local management API.
//
// The API listens on 127.0.0.1 but runs inside an elevated process and can
// change config, register a logon task and open Explorer. Binding to loopback
// alone does not stop a web page in the user's browser from sending requests
// to it (CSRF), nor a DNS-rebinding page from reading responses. This gate:
//
//   1. Requires the Host header to name the loopback listener itself
//      (127.0.0.1:<port> or localhost:<port>) to defeat DNS rebinding.
//   2. Rejects any request whose Origin is present and not the UI's own
//      origin (plus an optional developer origin from PROXYCLAW_DEV_URL).
//   3. Requires a per-launch random session token on every /api/ request,
//      delivered either as the HttpOnly SameSite=Strict cookie set by
//      GET /api/session?t=<token> or as the X-ProxyClaw-Token header
//      (test harnesses).
//
// The token is generated with BCryptGenRandom on each launch unless
// PROXYCLAW_API_TOKEN supplies one (>= 32 chars), which lets e2e harnesses
// talk to the API. Static frontend assets stay public: they contain no
// secrets and the token is never embedded in them.
//
// Isolating the API from other local processes of the same user is out of
// scope here; that needs an ACL'd named pipe or host IPC.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace clew::transport {

inline constexpr std::string_view kSessionCookie = "proxyclaw_session";
inline constexpr std::string_view kTokenHeader   = "X-ProxyClaw-Token";
inline constexpr std::string_view kSessionPath   = "/api/session";

enum class auth_verdict {
    allow,
    bad_host,       // 421 Misdirected Request
    bad_origin,     // 403
    missing_token,  // 401
};

// Constant-time comparison: avoids leaking the token length-prefix via timing.
[[nodiscard]] inline bool constant_time_equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

[[nodiscard]] inline std::string ascii_lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](unsigned char c) {
        return static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    });
    return out;
}

// Extracts one cookie value from a Cookie header ("a=1; b=2").
[[nodiscard]] inline std::string_view cookie_value(std::string_view header, std::string_view name) noexcept {
    while (!header.empty()) {
        const auto semi = header.find(';');
        std::string_view part = header.substr(0, semi);
        while (!part.empty() && part.front() == ' ') part.remove_prefix(1);
        if (part.size() > name.size() && part.starts_with(name) && part[name.size()] == '=') {
            return part.substr(name.size() + 1);
        }
        if (semi == std::string_view::npos) break;
        header.remove_prefix(semi + 1);
    }
    return {};
}

// Reduces "http://host:port/path?x" to "http://host:port" (lower-cased).
[[nodiscard]] inline std::string origin_of(std::string_view url) {
    const auto scheme = url.find("://");
    if (scheme == std::string_view::npos) return {};
    const auto path = url.find_first_of("/?#", scheme + 3);
    return ascii_lower(url.substr(0, path));
}

class api_auth {
public:
    api_auth(int port, std::string token) : port_(port), token_(std::move(token)) {
        const std::string p = std::to_string(port);
        hosts_   = {"127.0.0.1:" + p, "localhost:" + p};
        origins_ = {"http://127.0.0.1:" + p, "http://localhost:" + p};
    }

    void allow_origin(std::string_view url) {
        if (auto o = origin_of(url); !o.empty()) origins_.push_back(std::move(o));
    }

    [[nodiscard]] const std::string& token() const noexcept { return token_; }
    [[nodiscard]] int port() const noexcept { return port_; }

    [[nodiscard]] bool host_allowed(std::string_view host) const {
        const auto h = ascii_lower(host);
        return std::ranges::find(hosts_, h) != hosts_.end();
    }

    [[nodiscard]] bool origin_allowed(std::string_view origin) const {
        if (origin.empty()) return true;  // same-origin GETs and non-browser clients
        const auto o = ascii_lower(origin);
        return std::ranges::find(origins_, o) != origins_.end();
    }

    [[nodiscard]] bool token_matches(std::string_view candidate) const noexcept {
        return !candidate.empty() && constant_time_equal(candidate, token_);
    }

    // Pure decision function so it can be unit tested without httplib.
    [[nodiscard]] auth_verdict check(std::string_view path,
                                     std::string_view host,
                                     std::string_view origin,
                                     std::string_view cookie_header,
                                     std::string_view token_header) const {
        if (!host_allowed(host)) return auth_verdict::bad_host;
        if (!origin_allowed(origin)) return auth_verdict::bad_origin;
        if (!path.starts_with("/api/") && path != "/api") return auth_verdict::allow;
        if (path == kSessionPath) return auth_verdict::allow;  // validates ?t= itself
        if (token_matches(token_header)) return auth_verdict::allow;
        if (token_matches(cookie_value(cookie_header, kSessionCookie))) return auth_verdict::allow;
        return auth_verdict::missing_token;
    }

    [[nodiscard]] std::string session_cookie() const {
        return std::string(kSessionCookie) + "=" + token_ +
               "; Path=/; HttpOnly; SameSite=Strict";
    }

    [[nodiscard]] std::string bootstrap_path() const {
        return std::string(kSessionPath) + "?t=" + token_;
    }

private:
    int port_;
    std::string token_;
    std::vector<std::string> hosts_;
    std::vector<std::string> origins_;
};

// Token from PROXYCLAW_API_TOKEN when it is long enough, else `fallback`.
[[nodiscard]] inline std::string token_from_env_or(std::string fallback) {
    if (const char* env = std::getenv("PROXYCLAW_API_TOKEN"); env && std::string_view(env).size() >= 32) {
        return std::string(env);
    }
    return fallback;
}

} // namespace clew::transport
