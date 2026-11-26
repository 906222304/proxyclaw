#pragma once
#include <asio.hpp>
#include <cstdint>
#include <chrono>
#include <string>
#include <thread>
#include "proxy/socks5_credentials.hpp"
namespace clew {
namespace fake_forwarder {
inline bool start_ok = true;
inline int starts = 0;
inline int active = 0;
inline bool tcp_only = false;
inline int start_delay_ms = 0;
inline socks5_credentials last_creds{};
inline void reset() {
    start_ok = true; starts = 0; active = 0; tcp_only = false;
    start_delay_ms = 0; last_creds = {};
}
}
struct DnsForwarderStats {
    size_t   pending{0};
    size_t   max_pending{1024};
    size_t   pending_peak{0};
    size_t   tcp_active{0};
    size_t   max_tcp{64};
    size_t   tcp_peak{0};
    uint64_t dropped_pending_cap{0};
    uint64_t dropped_tcp_cap{0};
};
class dns_forwarder {
public:
    dns_forwarder(asio::io_context&, const std::string&, uint16_t,
                  const std::string&, uint16_t, const std::string&, uint16_t,
                  socks5_credentials creds = {}) {
        fake_forwarder::last_creds = std::move(creds);
    }
    ~dns_forwarder() { stop(); }
    bool start() {
        if (fake_forwarder::start_delay_ms)
            std::this_thread::sleep_for(std::chrono::milliseconds(fake_forwarder::start_delay_ms));
        ++fake_forwarder::starts;
        if (!fake_forwarder::start_ok) return false;
        running_ = true;
        ++fake_forwarder::active;
        return true;
    }
    bool tcp_only() const { return fake_forwarder::tcp_only; }
    DnsForwarderStats stats() const { return {}; }
    void stop() {
        if (running_) { --fake_forwarder::active; running_ = false; }
    }
private:
    bool running_ = false;
};
}
