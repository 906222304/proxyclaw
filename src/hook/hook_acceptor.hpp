#pragma once

// Hook mode relay listener: 127.0.0.1:0 (or [::1]:0). An injected process
// connects here instead of its real destination; the flow published under
// its source port says where it meant to go and through which group.

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <memory>

#include "core/log.hpp"
#include "hook/hook_flow_table.hpp"
#include "proxy/ipv6_egress.hpp"
#include "proxy/proxy_group_table.hpp"
#include "proxy/relay.hpp"

namespace clew::hook {

class acceptor {
public:
    acceptor(asio::io_context& ioc, flow_table& flows, const proxy_group_table& groups,
             bool ipv6, ipv6_egress* egress = nullptr)
        : ioc_(ioc), flows_(flows), groups_(groups), ipv6_(ipv6), egress_(egress) {}

    // The bound port, or 0 when the listener cannot be opened (no IPv6).
    uint16_t start() {
        try {
            const asio::ip::tcp::endpoint ep(
                ipv6_ ? asio::ip::address(asio::ip::address_v6::loopback())
                      : asio::ip::address(asio::ip::address_v4::loopback()), 0);
            acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(ioc_.get_executor(), ep);
        } catch (const std::exception& e) {
            PC_LOG_WARN("[HOOK-ACCEPT{}] cannot listen: {}", ipv6_ ? "-V6" : "", e.what());
            acceptor_.reset();
            return 0;
        }
        port_ = acceptor_->local_endpoint().port();
        running_ = true;
        asio::co_spawn(ioc_, accept_loop(), asio::detached);
        PC_LOG_INFO("[HOOK-ACCEPT{}] listening on port {}", ipv6_ ? "-V6" : "", port_);
        return port_;
    }

    void stop() {
        running_ = false;
        if (acceptor_ && acceptor_->is_open()) {
            std::error_code ec;
            acceptor_->close(ec);
        }
    }

    uint16_t port() const { return port_; }
    uint64_t accepted() const { return accepted_.load(); }
    uint64_t unmatched() const { return unmatched_.load(); }

private:
    asio::awaitable<void> accept_loop() {
        while (running_) {
            auto [ec, sock] = co_await acceptor_->async_accept(asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (running_) PC_LOG_DEBUG("[HOOK-ACCEPT] accept error: {}", ec.message());
                break;
            }
            accepted_.fetch_add(1);
            asio::co_spawn(asio::make_strand(ioc_), serve(std::move(sock)), asio::detached);
        }
    }

    asio::awaitable<void> serve(asio::ip::tcp::socket sock) {
        std::error_code ec;
        const auto peer = sock.remote_endpoint(ec);
        if (ec) co_return;
        const uint16_t src_port = peer.port();
        const auto f = flows_.take(ipv6_, src_port);
        if (!f) {
            unmatched_.fetch_add(1);
            PC_LOG_DEBUG("[HOOK-ACCEPT] no flow for port {}", src_port);
            co_return;
        }
        const auto cfg = groups_.find(f->group_id);
        if (!cfg) {
            PC_LOG_WARN("[HOOK-ACCEPT] group {} not found for port {}", f->group_id, src_port);
            co_return;
        }
        socks5_dest dest;
        dest.ipv6 = f->ipv6;
        dest.v4_host = f->v4_host;
        dest.v6 = f->v6;
        dest.port = f->port;
        co_await relay_through_proxy(sock, *cfg, dest, src_port, [] {},
                                     std::chrono::seconds(10), egress_, f->group_id);
    }

    asio::io_context& ioc_;
    flow_table& flows_;
    const proxy_group_table& groups_;
    const bool ipv6_;
    ipv6_egress* egress_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    uint16_t port_{0};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> accepted_{0};
    std::atomic<uint64_t> unmatched_{0};
};

} // namespace clew::hook
