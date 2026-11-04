#include "services/icon_service.hpp"

#include "api/icon_cache.hpp"

namespace clew {

icon_service::icon_service(icon_cache& cache) : cache_(cache) {}

std::vector<std::uint8_t> icon_service::get(std::string_view name, std::string_view path) {
    return cache_.get_icon_by_name(name, path);
}

} // namespace clew
