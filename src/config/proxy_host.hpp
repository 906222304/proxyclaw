#pragma once

// One normalisation for every place that resolves a proxy group's host
// (TCP relay, UDP associate session, speed test), so a value that passes the
// speed test also works for real traffic. Header-only, no dependencies.

#include <cctype>
#include <string>
#include <string_view>

namespace clew {

// Trim ASCII whitespace and strip one pair of surrounding [] (IPv6 literal).
inline std::string normalize_proxy_host(std::string_view host) {
    auto is_space = [](char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; };
    while (!host.empty() && is_space(host.front())) host.remove_prefix(1);
    while (!host.empty() && is_space(host.back()))  host.remove_suffix(1);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    return std::string(host);
}

} // namespace clew
