#include "services/config_service.hpp"

#include <format>
#include <string>

#include <nlohmann/json.hpp>

#include "common/api_exception.hpp"
#include "config/config_store.hpp"
#include "config/proxy_group_validation.hpp"

namespace clew {

config_service::config_service(config_store& cfg) : cfg_(cfg) {}

std::string config_service::get_raw() const {
    return cfg_.raw_json();
}

void config_service::replace_raw(std::string_view raw) {
    // The settings editor can rewrite proxy_groups wholesale. Apply the same
    // checks as /api/proxy-groups so a port like 70000 is rejected instead of
    // being truncated to 4464 on load. Malformed JSON is left to the store,
    // which reports it with its own message.
    const auto j = nlohmann::json::parse(raw, nullptr, /*allow_exceptions=*/false);
    if (!j.is_discarded() && j.is_object()) {
        if (auto it = j.find("proxy_groups"); it != j.end() && it->is_array()) {
            for (std::size_t i = 0; i < it->size(); ++i) {
                proxy_group_input in;
                if (auto err = parse_proxy_group_input((*it)[i], in)) {
                    throw api_exception{api_error::invalid_argument,
                                        std::format("proxy_groups[{}]: {}", i, err->message),
                                        nlohmann::json{{"field", err->field}, {"index", i}}};
                }
            }
        }
    }
    cfg_.replace_from_json(raw);
}

} // namespace clew
