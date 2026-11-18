#include "services/icon_service.hpp"

#include "api/icon_cache.hpp"

namespace clew {

icon_service::icon_service(icon_cache& cache) : cache_(cache) {}

std::shared_ptr<const std::vector<std::uint8_t>>
icon_service::get(std::uint32_t pid, std::string_view name) {
    return cache_.get_icon_for_process(pid, name);
}

} // namespace clew
