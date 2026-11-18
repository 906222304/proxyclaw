// /api/icon?pid=N&name=exe-name — returns PNG bytes.
// The server resolves the image path from `pid` (a client-supplied path is
// no longer accepted); `name` guards against PID reuse and is the fallback
// when the process is gone. Either may be omitted, not both.
// 200 + image/png when an icon exists, 204 No Content (empty body) when the
// exe has no extractable icon, 400 when both are missing or pid is invalid.

#include <charconv>
#include <cstdint>
#include <string>
#include <vector>

#include <httplib.h>

#include "common/api_context.hpp"
#include "common/api_exception.hpp"
#include "services/icon_service.hpp"
#include "transport/response_utils.hpp"
#include "transport/route_def.hpp"
#include "transport/route_registry.hpp"

namespace clew {

namespace {

void handle_icon(const httplib::Request& req, httplib::Response& res, const api_context& ctx) {
    std::string name = req.has_param("name") ? req.get_param_value("name") : std::string{};
    std::uint32_t pid = 0;
    if (req.has_param("pid")) {
        const std::string v = req.get_param_value("pid");
        const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), pid);
        if (ec != std::errc{} || end != v.data() + v.size()) {
            throw api_exception{api_error::invalid_argument, "pid must be a non-negative integer"};
        }
    }
    if (name.empty() && pid == 0) {
        throw api_exception{api_error::invalid_argument, "pid or name parameter required"};
    }

    const auto png = ctx.icons.get(pid, name);
    if (!png || png->empty()) {
        // "No icon" is a normal answer, not an error: 204 keeps the browser
        // console clean while the frontend shows its generic icon. Not cached
        // by the browser: the exe may become resolvable later (the server
        // retries failed lookups with backoff).
        res.status = 204;
        res.set_header("Cache-Control", "no-store");
        return;
    }
    // Keyed by PID, which Windows reuses: the frontend keeps its own cache,
    // so the browser must not serve an old process's icon for a new one.
    res.set_header("Cache-Control", "no-store");
    res.set_content(
        std::string(reinterpret_cast<const char*>(png->data()), png->size()),
        "image/png");
}

} // namespace

void register_icon_handlers(route_registry& r) {
    r.add({http_method::get, "/api/icon", &handle_icon});
}

} // namespace clew
