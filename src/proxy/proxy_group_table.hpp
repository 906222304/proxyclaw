#pragma once

// proxy_group_table — the TCP relay's view of the configured proxy groups.
//
// Written by the config observer (API worker threads), read by every relay
// coroutine on the IO workers. The map is never mutated in place: a writer
// builds a complete new map and publishes it with one pointer swap, so a
// reader holds a consistent immutable snapshot for as long as it keeps the
// shared_ptr. The mutex only guards the pointer copy (a refcount increment),
// never a map operation, and there is no strand hop per connection.
// (std::atomic<std::shared_ptr> would do the same, but libc++ — used by the
// zig-built local harnesses — does not provide it.)
//
// Header-only and free of asio/Windows so the unit tests can exercise it.

#include <mutex>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace clew {

// ProxyGroupConfig for relay (matches v3 architecture groups_ map value)
struct ProxyGroupConfig {
    std::string host;
    uint16_t    port{7890};
    bool operator==(const ProxyGroupConfig&) const = default;
};

using ProxyGroupMap = std::unordered_map<uint32_t, ProxyGroupConfig>;

class proxy_group_table {
public:
    using snapshot = std::shared_ptr<const ProxyGroupMap>;

    proxy_group_table() : current_(std::make_shared<const ProxyGroupMap>()) {}

    proxy_group_table(const proxy_group_table&)            = delete;
    proxy_group_table& operator=(const proxy_group_table&) = delete;

    // Replace the whole table. Readers that already loaded the previous
    // snapshot keep using it until they drop their reference.
    void publish(ProxyGroupMap next) {
        auto fresh = std::make_shared<const ProxyGroupMap>(std::move(next));
        std::scoped_lock lk(mu_);
        current_.swap(fresh);
        // the previous snapshot is released outside the lock (fresh's dtor)
    }

    [[nodiscard]] snapshot load() const {
        std::scoped_lock lk(mu_);
        return current_;
    }

    [[nodiscard]] std::optional<ProxyGroupConfig> find(uint32_t id) const {
        const auto s = load();
        if (auto it = s->find(id); it != s->end()) return it->second;
        return std::nullopt;
    }

    [[nodiscard]] std::size_t size() const { return load()->size(); }

private:
    mutable std::mutex mu_;
    snapshot           current_;
};

} // namespace clew
