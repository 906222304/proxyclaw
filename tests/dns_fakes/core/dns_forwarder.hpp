#pragma once
#include <asio.hpp>
#include <cstdint>
#include <string>
namespace clew {
namespace fake_forwarder {
inline bool start_ok = true;
inline int starts = 0;
inline int active = 0;
inline void reset() { start_ok = true; starts = 0; active = 0; }
}
class dns_forwarder {
public:
    dns_forwarder(asio::io_context&, const std::string&, uint16_t,
                  const std::string&, uint16_t, const std::string&, uint16_t) {}
    ~dns_forwarder() { stop(); }
    bool start() {
        ++fake_forwarder::starts;
        if (!fake_forwarder::start_ok) return false;
        running_ = true;
        ++fake_forwarder::active;
        return true;
    }
    void stop() {
        if (running_) { --fake_forwarder::active; running_ = false; }
    }
private:
    bool running_ = false;
};
}
