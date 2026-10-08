#pragma once
#include <cstdlib>
#include <iostream>
// The network regression compiles real sockets/protocols without Quill.
namespace clew::network_test {
template <typename... Args> void log(Args&&... args) {
    if (std::getenv("PROXYCLAW_DNS_TEST_LOG")) {
        ((std::cerr << args << ' '), ...);
        std::cerr << '\n';
    }
}
} // namespace clew::network_test
#define PC_LOG_INFO(...) ::clew::network_test::log(__VA_ARGS__)
#define PC_LOG_DEBUG(...) ::clew::network_test::log(__VA_ARGS__)
#define PC_LOG_WARN(...) ::clew::network_test::log(__VA_ARGS__)
#define PC_LOG_ERROR(...) ::clew::network_test::log(__VA_ARGS__)
