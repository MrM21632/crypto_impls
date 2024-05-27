#include "md5.hpp"
#include <iostream>


uint32_t reverse_bytes(uint32_t val) {
    return (
        (uint32_t) (val & 0xff) << 24 |
        (uint32_t) (val >> 8 & 0xff) << 16 |
        (uint32_t) (val >> 16 & 0xff) << 8 |
        (uint32_t) (val >> 24 & 0xff)
    );
}


int main() {
    std::vector<std::string> test_messages = {
        "",
        "a",
        "abc",
        "message digest",
        "the quick brown fox jumps over the lazy dog",
        "the quick brown fox jumps over the lazy dog.",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    };

    MD5Impl hash;
    for (std::string message : test_messages) {
        std::array<uint32_t, 4> result = hash.digest_message(message);

        std::cout << message << ": ";
        for (const auto& val : result) {
            std::cout << std::hex << reverse_bytes(val);
        }
        std::cout << std::endl;
    }
}