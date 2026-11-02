// Unit tests for the management API request gate (src/transport/api_auth.hpp).
// Pure logic: no sockets, no httplib, no Windows APIs.
#include "transport/api_auth.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x))                                                                                  \
            throw std::runtime_error(#x);                                                          \
    } while (false)

using clew::transport::api_auth;
using clew::transport::auth_verdict;
using clew::transport::cookie_value;

int main() {
    try {
        const std::string token(64, 'a');
        api_auth auth(18080, token);
        const std::string cookie = "proxyclaw_session=" + token;

        // Host header: only the loopback listener itself (DNS rebinding guard).
        CHECK(auth.check("/", "127.0.0.1:18080", "", "", "") == auth_verdict::allow);
        CHECK(auth.check("/", "LOCALHOST:18080", "", "", "") == auth_verdict::allow);
        CHECK(auth.check("/", "evil.example:18080", "", "", "") == auth_verdict::bad_host);
        CHECK(auth.check("/", "127.0.0.1:18081", "", "", "") == auth_verdict::bad_host);
        CHECK(auth.check("/", "", "", "", "") == auth_verdict::bad_host);
        CHECK(auth.check("/api/stats", "evil.example:18080", "", cookie, token) == auth_verdict::bad_host);
        std::cout << "PASS host validation\n";

        // Origin: absent or the UI's own origin only.
        CHECK(auth.check("/api/stats", "127.0.0.1:18080", "http://127.0.0.1:18080", cookie, "") == auth_verdict::allow);
        CHECK(auth.check("/api/stats", "127.0.0.1:18080", "https://evil.example", cookie, "") == auth_verdict::bad_origin);
        CHECK(auth.check("/api/stats", "127.0.0.1:18080", "null", cookie, "") == auth_verdict::bad_origin);
        CHECK(auth.check("/", "127.0.0.1:18080", "https://evil.example", "", "") == auth_verdict::bad_origin);
        std::cout << "PASS origin validation\n";

        // Token: every /api/ path except the bootstrap needs cookie or header.
        CHECK(auth.check("/api/stats", "127.0.0.1:18080", "", "", "") == auth_verdict::missing_token);
        CHECK(auth.check("/api/config", "127.0.0.1:18080", "", "proxyclaw_session=wrong", "") == auth_verdict::missing_token);
        CHECK(auth.check("/api/config", "127.0.0.1:18080", "", "", std::string(63, 'a')) == auth_verdict::missing_token);
        CHECK(auth.check("/api/config", "127.0.0.1:18080", "", "", token) == auth_verdict::allow);
        CHECK(auth.check("/api/config", "127.0.0.1:18080", "", "theme=dark; " + cookie, "") == auth_verdict::allow);
        CHECK(auth.check("/api", "127.0.0.1:18080", "", "", "") == auth_verdict::missing_token);
        CHECK(auth.check("/api/session", "127.0.0.1:18080", "", "", "") == auth_verdict::allow);
        CHECK(auth.check("/assets/index.js", "127.0.0.1:18080", "", "", "") == auth_verdict::allow);
        std::cout << "PASS session token\n";

        // Developer origin from PROXYCLAW_DEV_URL.
        CHECK(auth.check("/api/stats", "127.0.0.1:18080", "http://localhost:5173", cookie, "") == auth_verdict::bad_origin);
        auth.allow_origin("http://localhost:5173/some/path?q=1");
        CHECK(auth.check("/api/stats", "127.0.0.1:18080", "http://localhost:5173", cookie, "") == auth_verdict::allow);
        std::cout << "PASS developer origin\n";

        // Helpers.
        CHECK(cookie_value("a=1; proxyclaw_session=xyz; b=2", "proxyclaw_session") == "xyz");
        CHECK(cookie_value("proxyclaw_session_old=1", "proxyclaw_session").empty());
        CHECK(cookie_value("", "proxyclaw_session").empty());
        CHECK(auth.session_cookie().find("HttpOnly") != std::string::npos);
        CHECK(auth.session_cookie().find("SameSite=Strict") != std::string::npos);
        CHECK(auth.bootstrap_path() == "/api/session?t=" + token);
        CHECK(!auth.token_matches(""));
        std::cout << "PASS helpers\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
    return 0;
}
