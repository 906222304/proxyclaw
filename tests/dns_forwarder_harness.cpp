// Native Windows test host. Real forwarder/sockets; only logging is replaced.
#include "core/dns_forwarder.hpp"
#include <iostream>

int main(int argc, char** argv) {
    try {
        if (argc != 5)
            return 2;
        asio::io_context app_ioc; // Deliberately never run: stop must still drain.
        clew::dns_forwarder forwarder(app_ioc, "127.0.0.1",
                                      static_cast<uint16_t>(std::stoi(argv[1])), "127.0.0.1",
                                      static_cast<uint16_t>(std::stoi(argv[2])), "203.0.113.53", 53,
                                      std::chrono::milliseconds(std::stoi(argv[3])),
                                      std::chrono::milliseconds(std::stoi(argv[4])));
        if (!forwarder.start()) {
            std::cout << "FAILED" << std::endl;
            return 1;
        }
        std::cout << "READY" << std::endl;
        std::string command;
        std::getline(std::cin, command);
        forwarder.stop();
        // A second stop and the destructor must be harmless.
        forwarder.stop();
        std::cout << "STOPPED" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
