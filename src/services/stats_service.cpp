#include "services/stats_service.hpp"

#include <cstdint>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "domain/process_tree_manager.hpp"

namespace clew {

stats_service::stats_service(strand_bound_manager& exec, std::function<nlohmann::json()> traffic)
    : exec_(exec), traffic_(std::move(traffic)) {}

nlohmann::json stats_service::get_stats() const {
    auto j = exec_.query([](const domain::process_tree_manager& m) -> nlohmann::json {
        nlohmann::json out;
        out["hijacked_pids"]    = m.rules().get_hijacked_pids(m.tree()).size();
        out["auto_rules_count"] = m.rules().auto_rules().size();
        // Harness readiness signal: initial rundown verified against the OS
        // process list (see process_tree_manager::schedule_rundown_grace).
        out["tree_ready"]       = m.is_tree_ready();
        out["process_count"]    = m.tree().alive_count();
        return out;
    });
    if (traffic_) {
        auto t = traffic_();
        // IPv6 is not proxied yet: CONNECTs to IPv6 remotes are ignored by
        // the SOCKET layers and go direct. Surfaced top-level for the UI.
        const auto count = [&t](const char* layer) -> std::uint64_t {
            if (!t.contains(layer)) return 0;
            return t[layer].value("ipv6_unmanaged", std::uint64_t{0});
        };
        j["ipv6_unmanaged"] = {{"tcp", count("socket")}, {"udp", count("udp_socket")}};
        j["tcp_syn_parking"] = std::move(t);
    }
    return j;
}

nlohmann::json stats_service::get_env() {
    auto read_env = [](const char* name) -> std::string {
        DWORD size = GetEnvironmentVariableA(name, nullptr, 0);
        if (size == 0) return {};
        std::string buf(size - 1, '\0');
        GetEnvironmentVariableA(name, buf.data(), size);
        return buf;
    };

    nlohmann::json j;
    j["HTTP_PROXY"]  = read_env("HTTP_PROXY");
    j["HTTPS_PROXY"] = read_env("HTTPS_PROXY");
    j["NO_PROXY"]    = read_env("NO_PROXY");
    j["http_proxy"]  = read_env("http_proxy");
    j["https_proxy"] = read_env("https_proxy");
    j["no_proxy"]    = read_env("no_proxy");
    return j;
}

} // namespace clew
