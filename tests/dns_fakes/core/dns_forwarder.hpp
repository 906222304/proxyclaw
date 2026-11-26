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
    void stop() {
        if (running_) { --fake_forwarder::active; running_ = false; }
    }
private:
    bool running_ = false;
};
}
