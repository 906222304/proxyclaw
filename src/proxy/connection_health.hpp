#pragma once

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <chrono>
#include <exception>
#include <mstcpip.h>

#include "core/log.hpp"

namespace clew {

// Apply only to TCP transport health. Application silence is not a timeout:
// a healthy idle tunnel must remain usable for long-running conversations.
inline void enable_tcp_keepalive(asio::ip::tcp::socket& socket) {
    tcp_keepalive settings{1, 60'000, 10'000};
    DWORD returned = 0;
    if (WSAIoctl(socket.native_handle(), SIO_KEEPALIVE_VALS,
                 &settings, sizeof(settings), nullptr, 0, &returned,
                 nullptr, nullptr) == SOCKET_ERROR) {
        PC_LOG_WARN("[PROXY] TCP keepalive setup failed: {}", WSAGetLastError());
    }
}

inline asio::awaitable<std::exception_ptr>
capture_setup_error(asio::awaitable<void> operation) {
    try { co_await std::move(operation); }
    catch (...) { co_return std::current_exception(); }
    co_return nullptr;
}

// operator|| waits for the first *successful* coroutine. Capture errors as
// values so a rejected handshake fails immediately instead of waiting for the
// deadline. The losing branch is cancelled and joined before locals expire.
inline asio::awaitable<void>
with_setup_deadline(asio::awaitable<void> operation,
                    std::chrono::steady_clock::duration timeout = std::chrono::seconds(10)) {
    using asio::experimental::awaitable_operators::operator||;
    asio::steady_timer timer(co_await asio::this_coro::executor, timeout);
    auto result = co_await (capture_setup_error(std::move(operation)) ||
                           timer.async_wait(asio::use_awaitable));
    if (result.index() == 1)
        throw asio::system_error(asio::error::timed_out);
    if (auto error = std::get<0>(result)) std::rethrow_exception(error);
}

} // namespace clew
