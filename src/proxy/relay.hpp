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

#include "core/port_tracker.hpp"
#include "proxy/socks5_async.hpp"
#include "proxy/connection_health.hpp"

// Format host-byte-order IPv4 as dotted string
inline std::string ip_host_to_string(uint32_t ip) {
    return std::format("{}.{}.{}.{}",
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF,  ip & 0xFF);
}

namespace clew {

using asio::ip::tcp;
using asio::experimental::awaitable_operators::operator&&;

// ProxyGroupConfig for relay (matches v3 architecture groups_ map value)
struct ProxyGroupConfig {
    std::string host;
    uint16_t    port{7890};
};

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

// Handle a single redirected connection.
// Reads tracker entry, connects to SOCKS5 proxy, relays bidirectionally.
//
// Parameters:
//   client_sock:    accepted socket from local listener (redirected app connection)
//   tracker:        port tracker to lookup original destination
//   strand:         strand protecting groups_ map
//   groups:         proxy group config map (read on strand)
//   setup_timeout:  total resolution/connect/handshake deadline
inline asio::awaitable<void>
handle_connection(tcp::socket client_sock,
                  PortTracker& tracker,
                  asio::strand<asio::io_context::executor_type>& strand,
                  const std::unordered_map<uint32_t, ProxyGroupConfig>& groups,
                  std::chrono::steady_clock::duration setup_timeout = std::chrono::seconds(10))
{
    auto ex = co_await asio::this_coro::executor;

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
    const TrackerEntry* entry = &taken->entry;
    const int64_t flow_ts = taken->connect_ts;

    // All tracker retirements happen on the strand (single writer for state
    // transitions out of a decided slot); the relay only asks for one.
    auto release_slot = [&tracker, &strand, src_port, flow_ts]() {
        asio::post(strand, [&tracker, src_port, flow_ts]() {
            tracker.retire_if(src_port, flow_ts);
        });
    };

    // Query group config on strand (enter strand, read, exit immediately)
    struct GroupInfo {
        std::string host;
        uint16_t port;
    };

    auto cfg_opt = co_await asio::co_spawn(strand,
        [&groups, group_id = entry->group_id]() -> asio::awaitable<std::optional<GroupInfo>> {
            auto it = groups.find(group_id);
            if (it == groups.end()) co_return std::nullopt;
            co_return GroupInfo{it->second.host, it->second.port};
        }, asio::use_awaitable);

    if (!cfg_opt) {
        PC_LOG_WARN("[RELAY] Group {} not found for port {}", entry->group_id, src_port);
        release_slot();
        co_return;
    }

    auto dest_addr = entry->remote_addr[0];
    auto dest_port = entry->remote_port;

    // DNS redirect: TCP:53 connections from proxied processes → use clean DNS server
    // Prevents DNS pollution when Chromium's built-in resolver queries local DNS directly
    if (dest_port == 53) {
        // 8.8.8.8 in host byte order = 0x08080808
        auto orig = dest_addr;
        dest_addr = 0x08080808;
        PC_LOG_DEBUG("[RELAY] DNS redirect port={} {}:53 -> 8.8.8.8:53",
                      src_port, ip_host_to_string(orig));
    }

    auto dest_ip_str = ip_host_to_string(dest_addr);

    try {
        auto t0 = std::chrono::steady_clock::now();

        enable_tcp_keepalive(client_sock);
        tcp::resolver resolver{ex};
        tcp::socket proxy_sock{ex};
        auto t1 = t0;
        auto setup = [&]() -> asio::awaitable<void> {
            auto eps = co_await resolver.async_resolve(
                cfg_opt->host, std::to_string(cfg_opt->port), asio::use_awaitable);
            co_await asio::async_connect(proxy_sock, eps, asio::use_awaitable);
            enable_tcp_keepalive(proxy_sock);
            t1 = std::chrono::steady_clock::now();
            co_await socks5_handshake(proxy_sock, dest_addr, dest_port);
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
    release_slot();
    PC_LOG_DEBUG("[RELAY] Closed port={} ({}:{})", src_port, dest_ip_str, dest_port);
}

} // namespace clew
