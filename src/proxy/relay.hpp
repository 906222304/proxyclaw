#pragma once

// Bidirectional relay using C++20 coroutines.
// Replaces thread-per-direction proxy_relay.hpp.
// Preserves TCP half-close; transport failures cancel both directions.
//
// 100 connections = 100 coroutines on io_context worker threads.
// Previous: 100 connections = 200 threads.

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <format>
#include "core/log.hpp"

#include "config/proxy_host.hpp"
#include "core/ipv6_flow_table.hpp"
#include "core/port_tracker.hpp"
#include "proxy/proxy_group_table.hpp"
#include "proxy/tcp_dns_upstream.hpp"
#include "proxy/socks5_async.hpp"
#include "proxy/connection_health.hpp"

// Format host-byte-order IPv4 as dotted string
inline std::string ip_host_to_string(uint32_t ip) {
    return std::format("{}.{}.{}.{}",
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF,  ip & 0xFF);
}

// "1.2.3.4" or "[2001:db8::1]" (for logs).
inline std::string dest_to_string(const clew::socks5_dest& d) {
    if (!d.ipv6) return ip_host_to_string(d.v4_host);
    std::array<unsigned char, 16> b{};
    std::copy(d.v6.begin(), d.v6.end(), b.begin());
    return "[" + asio::ip::address_v6(b).to_string() + "]";
}

namespace clew {

using asio::ip::tcp;
using asio::experimental::awaitable_operators::operator&&;

// Unidirectional pipe: read from `from`, write to `to`.
// EOF is a half-close: the opposite direction may still have a response.
// A transport error is fatal: close both sockets to wake the other read.
struct RelayPipeResult {
    uint64_t bytes{};
    asio::error_code end;
};

inline asio::awaitable<RelayPipeResult>
pipe(tcp::socket& from, tcp::socket& to, uint16_t port, const char* direction)
{
    std::array<char, 32 * 1024> buf{};
    uint64_t transferred = 0;
    try {
        for (;;) {
            auto n = co_await from.async_read_some(
                asio::buffer(buf), asio::use_awaitable);
            co_await asio::async_write(
                to, asio::buffer(buf, n), asio::use_awaitable);
            transferred += n;
        }
    } catch (const asio::system_error& e) {
        std::error_code ec;
        if (e.code() == asio::error::eof) {
            to.shutdown(tcp::socket::shutdown_send, ec);
        } else {
            if (e.code() != asio::error::operation_aborted)
                PC_LOG_WARN("[RELAY] Transport lost port={} direction={} after {} bytes: {}",
                            port, direction, transferred, e.what());
            from.close(ec);
            to.close(ec);
        }
        co_return RelayPipeResult{transferred, e.code()};
    } catch (...) {
        std::error_code ec;
        from.close(ec);
        to.close(ec);
        throw;
    }
}

// Connect to the group's SOCKS5 server, CONNECT to `dest`, relay both ways.
// `release` retires the flow's NAT state; called exactly once.
template <typename Release>
asio::awaitable<void>
relay_through_proxy(tcp::socket& client_sock, const ProxyGroupConfig& cfg, socks5_dest dest,
                    uint16_t src_port, Release release,
                    std::chrono::steady_clock::duration setup_timeout)
{
    auto ex = co_await asio::this_coro::executor;

    // DNS redirect: TCP:53 from proxied processes goes to the configured DNS
    // upstream (dns.upstream_host, fallback 8.8.8.8; proxy/tcp_dns_upstream.hpp).
    // Prevents DNS pollution when Chromium's built-in resolver queries local DNS directly.
    // The upstream is IPv4, whichever family the application used.
    if (dest.port == 53) {
        const auto up = tcp_dns::current();
        const auto orig = dest_to_string(dest);
        dest = socks5_dest{};
        dest.v4_host = up.ip;
        dest.port = up.port;
        PC_LOG_DEBUG("[RELAY] DNS redirect port={} {}:53 -> {}:{}",
                     src_port, orig, ip_host_to_string(up.ip), up.port);
    }

    const auto dest_ip_str = dest_to_string(dest);
    const auto dest_port = dest.port;

    try {
        auto t0 = std::chrono::steady_clock::now();

        enable_tcp_keepalive(client_sock);
        tcp::resolver resolver{ex};
        tcp::socket proxy_sock{ex};
        auto t1 = t0;
        auto setup = [&]() -> asio::awaitable<void> {
            auto eps = co_await resolver.async_resolve(
                normalize_proxy_host(cfg.host), std::to_string(cfg.port),
                asio::use_awaitable);
            co_await asio::async_connect(proxy_sock, eps, asio::use_awaitable);
            enable_tcp_keepalive(proxy_sock);
            t1 = std::chrono::steady_clock::now();
            co_await socks5_handshake(proxy_sock, dest);
        };
        co_await with_setup_deadline(setup(), setup_timeout);

        auto t2 = std::chrono::steady_clock::now();
        auto connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        auto handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        PC_LOG_INFO("[RELAY] OK port={} -> {}:{} (proxy connect={}ms, socks5={}ms)",
                     src_port, dest_ip_str, dest_port, connect_ms, handshake_ms);

        auto [up, down] = co_await (pipe(client_sock, proxy_sock, src_port, "up") &&
                                   pipe(proxy_sock, client_sock, src_port, "down"));
        auto lifetime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        PC_LOG_INFO("[RELAY] End port={} lifetime={}ms up={} down={} up_end={} down_end={}",
                    src_port, lifetime, up.bytes, down.bytes, up.end.message(), down.end.message());

    } catch (const std::exception& e) {
        PC_LOG_WARN("[RELAY] FAIL port={} -> {}:{} error: {}",
                     src_port, dest_ip_str, dest_port, e.what());
    }

    // Retire the relay entry while preserving queued FIN/ACK translation.
    release();
    PC_LOG_DEBUG("[RELAY] Closed port={} ({}:{})", src_port, dest_ip_str, dest_port);
}

// Handle a single redirected IPv4 connection.
// Reads tracker entry, connects to SOCKS5 proxy, relays bidirectionally.
//
// Parameters:
//   client_sock:    accepted socket from local listener (redirected app connection)
//   tracker:        port tracker to lookup original destination
//   strand:         strand that owns tracker slot retirement
//   groups:         immutable, atomically swapped proxy group snapshot
//   setup_timeout:  total resolution/connect/handshake deadline
inline asio::awaitable<void>
handle_connection(tcp::socket client_sock,
                  PortTracker& tracker,
                  asio::strand<asio::io_context::executor_type>& strand,
                  const proxy_group_table& groups,
                  std::chrono::steady_clock::duration setup_timeout = std::chrono::seconds(10))
{
    std::error_code ep_ec;
    auto ep = client_sock.remote_endpoint(ep_ec);
    if (ep_ec) co_return;  // socket already closed
    const uint16_t src_port = ep.port();

    // Lookup tracker entry. The CONNECT timestamp identifies *this* flow: the
    // app may close, reuse the port and get a fresh decision before we tear
    // down, and the cleanup below must not wipe that newer flow's slot.
    auto taken = tracker.take(src_port);
    if (!taken) {
        PC_LOG_DEBUG("[RELAY] No tracker entry for port {}", src_port);
        co_return;
    }
    const TrackerEntry entry = taken->entry;
    const int64_t flow_ts = taken->connect_ts;

    // All tracker retirements happen on the strand (single writer for state
    // transitions out of a decided slot); the relay only asks for one.
    auto release_slot = [&tracker, &strand, src_port, flow_ts]() {
        asio::post(strand, [&tracker, src_port, flow_ts]() {
            tracker.retire_if(src_port, flow_ts);
        });
    };

    // Lock-free read of the current group snapshot (published whole by the
    // config observer; never mutated in place).
    const auto cfg_opt = groups.find(entry.group_id);
    if (!cfg_opt) {
        PC_LOG_WARN("[RELAY] Group {} not found for port {}", entry.group_id, src_port);
        release_slot();
        co_return;
    }

    socks5_dest dest;
    dest.v4_host = entry.remote_addr[0];
    dest.port = entry.remote_port;
    co_await relay_through_proxy(client_sock, *cfg_opt, dest, src_port, release_slot, setup_timeout);
}

// Handle a single redirected IPv6 connection (ipv6.mode = proxy): the flow
// comes from the IPv6 flow table, the CONNECT carries ATYP 4.
inline asio::awaitable<void>
handle_connection_v6(tcp::socket client_sock,
                     ipv6_flow_table<>& flows,
                     const proxy_group_table& groups,
                     std::chrono::steady_clock::duration setup_timeout = std::chrono::seconds(10))
{
    std::error_code ep_ec;
    auto ep = client_sock.remote_endpoint(ep_ec);
    if (ep_ec) co_return;
    const uint16_t src_port = ep.port();

    const auto flow = flows.take(src_port);
    if (!flow) {
        PC_LOG_DEBUG("[RELAY] No IPv6 flow for port {}", src_port);
        co_return;
    }
    const uint64_t flow_id = flow->id;
    auto release = [&flows, src_port, flow_id]() {
        flows.retire(src_port, flow_id, std::chrono::steady_clock::now());
    };

    const auto cfg_opt = groups.find(flow->group_id);
    if (!cfg_opt) {
        PC_LOG_WARN("[RELAY] Group {} not found for IPv6 port {}", flow->group_id, src_port);
        release();
        co_return;
    }

    socks5_dest dest;
    dest.ipv6 = true;
    dest.v6 = flow->remote;
    dest.port = flow->remote_port;
    co_await relay_through_proxy(client_sock, *cfg_opt, dest, src_port, release, setup_timeout);
}

} // namespace clew
