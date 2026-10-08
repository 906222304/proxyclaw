#include "core/dns_wire.hpp"
#include <iostream>
#include <random>
#include <stdexcept>
using bytes = std::vector<uint8_t>;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x))                                                                                  \
            throw std::runtime_error(#x);                                                          \
    } while (false)
static bytes query() {
    return {0x12, 0x34, 1,   0,   0,   1, 0,   0,   0,   0,   0, 0, 7, 'e', 'x',
            'a',  'm',  'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0,   1};
}
int main() {
    try {
        auto q = query();
        auto response = clew::dns_wire::empty_response(q, 0);
        CHECK(clew::dns_wire::matches(response, q));
        response[13] = 'E';
        CHECK(clew::dns_wire::matches(response, q));
        response[13] = 'x';
        CHECK(!clew::dns_wire::matches(response, q));
        response = clew::dns_wire::empty_response(q, 0);
        response[0] ^= 1;
        CHECK(!clew::dns_wire::matches(response, q));
        response[0] ^= 1;
        response[2] ^= 8;
        CHECK(!clew::dns_wire::matches(response, q));
        CHECK(!clew::dns_wire::matches(q, q));
        std::cout << "PASS question, transaction ID, opcode and QR validation\n";

        auto two = q;
        two[5] = 2;
        two.insert(two.end(), q.begin() + 12, q.end());
        auto compressed = clew::dns_wire::empty_response(q, 0);
        compressed[5] = 2;
        compressed.insert(compressed.end(), {0xc0, 12, 0, 1, 0, 1});
        CHECK(clew::dns_wire::matches(compressed, two));
        auto invalid = q;
        invalid.resize(18);
        invalid[12] = 0xc0;
        invalid[13] = 12;
        CHECK(!clew::dns_wire::parse_questions(invalid));
        invalid[13] = 255;
        CHECK(!clew::dns_wire::parse_questions(invalid));
        invalid = q;
        invalid[12] = 64;
        CHECK(!clew::dns_wire::parse_questions(invalid));
        invalid = q;
        invalid.pop_back();
        CHECK(!clew::dns_wire::parse_questions(invalid));
        std::cout << "PASS compressed names, pointer cycles and malformed labels\n";

        q[3] = 0x10;
        auto failed = clew::dns_wire::empty_response(q, 2);
        CHECK(failed[0] == 0x12 && failed[1] == 0x34 && failed[2] == 0x81 && failed[3] == 0x92);
        for (size_t i = 6; i < 12; ++i)
            CHECK(failed[i] == 0);
        CHECK(clew::dns_wire::empty_response(q, 0, true)[2] == 0x83);
        std::cout << "PASS SERVFAIL and truncated reply flags\n";

        CHECK(clew::dns_wire::udp_limit(q) == 512);
        q[11] = 1;
        q.insert(q.end(), {0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0});
        CHECK(clew::dns_wire::udp_limit(q) == 1232);
        q[q.size() - 8] = 0xff;
        q[q.size() - 7] = 0xff;
        CHECK(clew::dns_wire::udp_limit(q) == 65507);
        q.pop_back();
        CHECK(clew::dns_wire::udp_limit(q) == 512);
        std::cout << "PASS EDNS size parsing and malformed OPT handling\n";

        std::mt19937 random(12345);
        for (size_t i = 0; i < 10000; ++i) {
            bytes input(random() % 256);
            for (auto& b : input)
                b = static_cast<uint8_t>(random());
            (void)clew::dns_wire::parse_questions(input);
            (void)clew::dns_wire::udp_limit(input);
            (void)clew::dns_wire::empty_response(input, 2);
            (void)clew::dns_wire::matches(input, query());
        }
        std::cout << "PASS bounded parser on 10000 random packets\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
