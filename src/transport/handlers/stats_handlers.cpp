// /api/stats + /api/env + /api/diagnostics/export.

#include <utility>

#include <httplib.h>

#include "common/api_context.hpp"
#include "services/diagnostics_service.hpp"
#include "services/stats_service.hpp"
#include "transport/response_utils.hpp"
#include "transport/route_def.hpp"
#include "transport/route_registry.hpp"

namespace clew {

namespace {

void handle_stats(const httplib::Request&, httplib::Response& res, const api_context& ctx) {
    write_json(res, ctx.stats.get_stats());
}

void handle_env(const httplib::Request&, httplib::Response& res, const api_context&) {
    write_json(res, stats_service::get_env());
}

void handle_diagnostics_export(const httplib::Request&, httplib::Response& res,
                               const api_context& ctx) {
    auto bundle = ctx.diagnostics.export_bundle();
    res.set_header("Content-Disposition",
                   "attachment; filename=\"" + bundle.filename + "\"");
    res.set_content(std::move(bundle.zip_bytes), "application/zip");
    res.status = 200;
}

} // namespace

void register_stats_handlers(route_registry& r) {
    r.add({http_method::get, "/api/stats",              &handle_stats});
    r.add({http_method::get, "/api/env",                &handle_env});
    r.add({http_method::get, "/api/diagnostics/export", &handle_diagnostics_export});
}

} // namespace clew
