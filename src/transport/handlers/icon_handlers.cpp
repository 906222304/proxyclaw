// /api/icon?name=exe-name[&path=exe-path] — returns PNG bytes.
// 200 + image/png when an icon exists, 204 No Content (empty body) when the
// exe has no extractable icon, 400 when `name` is missing.

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
    if (!req.has_param("name")) {
        throw api_exception{api_error::invalid_argument, "name parameter required"};
    }
    std::string name = req.get_param_value("name");
    std::string path = req.has_param("path") ? req.get_param_value("path") : std::string{};

    std::vector<std::uint8_t> png = ctx.icons.get(name, path);
    if (png.empty()) {
        // "No icon" is a normal answer, not an error: 204 keeps the browser
        // console clean while the frontend shows its generic icon. Not cached:
        // the exe may become resolvable later.
        res.status = 204;
        res.set_header("Cache-Control", "no-store");
        return;
    }
    res.set_header("Cache-Control", "public, max-age=86400");
    res.set_content(
        std::string(reinterpret_cast<const char*>(png.data()), png.size()),
        "image/png");
}

} // namespace

void register_icon_handlers(route_registry& r) {
    r.add({http_method::get, "/api/icon", &handle_icon});
}

} // namespace clew
