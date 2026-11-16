#pragma once

// Asio-based TCP acceptor for redirected connections.
// Replaces blocking local_listener.hpp.
// Binds to 127.0.0.1:0 (localhost, ephemeral port) and accepts
// connections redirected by the NETWORK layer. The IPv6 instance binds
// [::1]:0 and serves flows from the IPv6 flow table (ipv6.mode = proxy).

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <unordered_map>
#include "core/log.hpp"

#include "core/port_tracker.hpp"
#include "proxy/relay.hpp"

namespace clew {

using asio::ip::tcp;

class async_acceptor {
public:
    async_acceptor(asio::io_context& ioc,
                   PortTracker& tracker,
                   asio::strand<asio::io_context::executor_type>& strand,
                   const proxy_group_table& groups,
                   ipv6_flow_table<>* v6_flows = nullptr)
        : ioc_(ioc)
        , tracker_(tracker)
        , strand_(strand)
        , groups_(groups)
        , v6_flows_(v6_flows)
    {}

    // Start listening. Returns the bound port. The IPv6 instance returns 0
    // when [::1] cannot be bound (IPv6 disabled on the host).
    uint16_t start() {
        auto ex = ioc_.get_executor();
        if (v6_flows_) {
            try {
                tcp::endpoint ep(asio::ip::address_v6::loopback(), 0);
                acceptor_ = std::make_unique<tcp::acceptor>(ex, ep);
            } catch (const std::exception& e) {
                PC_LOG_WARN("[ACCEPTOR-V6] Cannot listen on [::1]: {} (IPv6 proxying off)", e.what());
                acceptor_.reset();
                return 0;
            }
        } else {
            tcp::endpoint ep(asio::ip::address_v4::loopback(), 0);
            acceptor_ = std::make_unique<tcp::acceptor>(ex, ep);
        }

        port_ = acceptor_->local_endpoint().port();
        PC_LOG_INFO("[ACCEPTOR{}] Listening on port {}", v6_flows_ ? "-V6" : "", port_);

        // Launch accept loop as coroutine
        asio::co_spawn(ioc_, accept_loop(), asio::detached);

        return port_;
    }

    void stop() {
        running_ = false;
        if (acceptor_ && acceptor_->is_open()) {
            std::error_code ec;
            acceptor_->close(ec);
        }
        PC_LOG_INFO("[ACCEPTOR] Stopped (accepted {} connections)", accepted_count_.load());
    }

    uint16_t port() const { return port_; }
    uint64_t accepted_count() const { return accepted_count_; }

private:
    asio::io_context& ioc_;
    PortTracker& tracker_;
    asio::strand<asio::io_context::executor_type>& strand_;
    const proxy_group_table& groups_;
    ipv6_flow_table<>* v6_flows_;

    std::unique_ptr<tcp::acceptor> acceptor_;
    uint16_t port_{0};
    std::atomic<bool> running_{true};
    std::atomic<uint64_t> accepted_count_{0};

    asio::awaitable<void> accept_loop() {
        while (running_) {
            auto [ec, sock] = co_await acceptor_->async_accept(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (running_)
                    PC_LOG_DEBUG("[ACCEPTOR] Accept error: {}", ec.message());
                break;
            }

            accepted_count_.fetch_add(1);

            // Spawn relay coroutine for this connection
            // Socket cancellation, deadline and both pipe completions for one
            // connection must be serialized even with multiple IO workers.
            if (v6_flows_)
                asio::co_spawn(asio::make_strand(ioc_),
                    handle_connection_v6(std::move(sock), *v6_flows_, groups_),
                    asio::detached);
            else
                asio::co_spawn(asio::make_strand(ioc_),
                    handle_connection(std::move(sock), tracker_, strand_, groups_),
                    asio::detached);
        }
    }
};

} // namespace clew
