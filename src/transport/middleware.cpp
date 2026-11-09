#include "transport/middleware.hpp"

#include <string_view>

#include <httplib.h>

#include "core/log.hpp"
#include "transport/api_auth.hpp"

namespace clew {

void install_auth_gate(httplib::Server& server, const transport::api_auth& auth) {
    server.set_pre_routing_handler([&auth](const httplib::Request& req, httplib::Response& res) {
        using transport::auth_verdict;
        const auto verdict = auth.check(
            req.path,
            req.get_header_value("Host"),
            req.get_header_value("Origin"),
            req.get_header_value("Cookie"),
            req.get_header_value(std::string(transport::kTokenHeader)));
        switch (verdict) {
        case auth_verdict::allow:
            return httplib::Server::HandlerResponse::Unhandled;
        case auth_verdict::bad_host:
            res.status = 421;
            break;
        case auth_verdict::bad_origin:
            res.status = 403;
            break;
        case auth_verdict::missing_token:
            res.status = 401;
            break;
        }
        res.set_header("Cache-Control", "no-store");
        res.set_content(R"({"error":"unauthorized"})", "application/json");
        PC_LOG_WARN("[api] rejected {} {} status={}", req.method, req.path, res.status);
        return httplib::Server::HandlerResponse::Handled;
    });
}

void install_session_route(httplib::Server& server, const transport::api_auth& auth) {
    server.Get(std::string(transport::kSessionPath), [&auth](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");
        if (!auth.token_matches(req.get_param_value("t"))) {
            res.status = 401;
            res.set_content(R"({"error":"unauthorized"})", "application/json");
            PC_LOG_WARN("[api] session bootstrap rejected");
            return;
        }
        res.set_header("Set-Cookie", auth.session_cookie());
        res.set_header("Referrer-Policy", "no-referrer");
        res.set_redirect("/", 302);
    });
}

void install_default_headers(httplib::Server& server) {
    // httplib allows only ONE post_routing_handler. The API is same-origin
    // only (see api_auth.hpp), so no Access-Control-* headers are sent.
    server.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        std::string_view path = req.path;
        if (path.starts_with("/api/")) {
            res.set_header("Cache-Control", "no-store");
        } else if (path.starts_with("/assets/")) {
            // Vite emits content-hashed filenames under /assets/. A code change
            // produces a new filename, so these can be cached forever and can
            // never serve stale code.
            res.set_header("Cache-Control", "public, max-age=31536000, immutable");
        } else {
            // index.html and SPA routes live at stable URLs ("/", "/index.html").
            // They MUST revalidate every load: cpp-httplib sends ETag +
            // Last-Modified but no Cache-Control, so WebView2 applies heuristic
            // caching and serves a stale index that references asset hashes which
            // no longer exist after a frontend rebuild (-> blank Settings / 404
            // lazy chunks). no-cache forces a conditional GET; the existing ETag
            // makes that a cheap 304 when unchanged. All localhost, so ~free.
            res.set_header("Cache-Control", "no-cache");
        }
    });
}

} // namespace clew
