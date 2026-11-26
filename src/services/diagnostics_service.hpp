#pragma once

// diagnostics_service — builds a sanitized diagnostic ZIP archive containing
// version/OS summary, /api/stats snapshot, redacted config, and recent log tail
// for one-click issue reporting (v0.18 #4).
//
// Layering (H1): no asio, no httplib, no cross-service includes.

#include <filesystem>
#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace clew {

class config_store;

struct diagnostics_export_result {
    std::string filename;
    std::string zip_bytes;
};

class diagnostics_service {
public:
    diagnostics_service(config_store& cfg,
                        std::function<nlohmann::json()> stats_fn,
                        std::function<nlohmann::json()> env_fn,
                        std::filesystem::path log_path,
                        std::string version);

    diagnostics_service(const diagnostics_service&)            = delete;
    diagnostics_service& operator=(const diagnostics_service&) = delete;

    [[nodiscard]] diagnostics_export_result export_bundle() const;

private:
    config_store&                   cfg_;
    std::function<nlohmann::json()> stats_fn_;
    std::function<nlohmann::json()> env_fn_;
    std::filesystem::path           log_path_;
    std::string                     version_;
};

} // namespace clew
