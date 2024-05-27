#include "sha512.hpp"
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
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    };

    SHA512t224Impl hash;
    for (std::string message : test_messages) {
        std::array<uint64_t, 8> result = hash.digest_message(message);

        std::cout << message << ": ";
        for (int i = 0; i < 3; ++i) {
            std::cout << std::hex << result[i];
        }
        std::cout << (uint32_t)(result[3] >> 32 & 0xffffffff);
        std::cout << std::endl;
    }
}