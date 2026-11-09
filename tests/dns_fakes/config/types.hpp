#pragma once
#include <cstdint>
#include <string>
namespace clew {
struct DnsConfig {
    bool enabled = false;
    std::string mode = "forwarder";
    std::string listen_host = "127.0.0.2";
    uint16_t listen_port = 53;
    std::string upstream_host = "8.8.8.8";
    uint16_t upstream_port = 53;
};
}
