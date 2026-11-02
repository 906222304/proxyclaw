#pragma once

// Global cross-cutting behaviors installed on the httplib::Server once.

namespace httplib { class Server; }

namespace clew::transport { class api_auth; }

namespace clew {

// Host / Origin / session-token gate for every request (see api_auth.hpp).
void install_auth_gate(httplib::Server& server, const transport::api_auth& auth);

// GET /api/session?t=<token>: sets the HttpOnly session cookie and redirects
// to the UI root. This is the only way a browser-hosted UI obtains the cookie.
void install_session_route(httplib::Server& server, const transport::api_auth& auth);

// Cache-Control headers for API and static responses. The API is same-origin
// only, so no CORS headers are emitted.
void install_default_headers(httplib::Server& server);

} // namespace clew
