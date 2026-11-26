#pragma once

// Optional RFC 1929 SOCKS5 username/password credentials.
// Kept free of Asio and Windows headers so services/ and config/ can share it.

#include <string>

namespace clew {

struct socks5_credentials {
    std::string user;
    std::string password;

    [[nodiscard]] bool empty() const noexcept { return user.empty() && password.empty(); }
    bool operator==(const socks5_credentials&) const = default;
};

} // namespace clew
