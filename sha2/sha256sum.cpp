#include "sha256.hpp"
#include <iostream>


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

    SHA256Impl hash;
    for (std::string message : test_messages) {
        std::array<uint32_t, 8> result = hash.digest_message(message);

        std::cout << message << ": ";
        for (const auto& val : result) {
            std::cout << std::hex << val;
        }
        std::cout << std::endl;
    }
}