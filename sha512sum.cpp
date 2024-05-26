#include "sha512.hpp"
#include <iostream>


int main() {
    std::vector<std::string> test_messages = {
        "",
        "a",
        "abc",
        "message digest",
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy dog.",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    };

    SHA512Impl hash;
    for (std::string message : test_messages) {
        std::array<uint64_t, 8> result = hash.digest_message(message);

        std::cout << message << ": ";
        for (const auto& val : result) {
            std::cout << std::hex << val;
        }
        std::cout << std::endl;
    }
}