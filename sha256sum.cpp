#include "sha256.hpp"
#include <iostream>


int main() {
    // TODO: Currently fails for non-empty messages, need to investigate
    std::vector<std::string> test_messages = {
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        "",
        // ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
        "a",
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        "abc",
        // f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650
        "message digest",
        // 05c6e08f1d9fdafa03147fcb8f82f124c76d2f70e3d989dc8aadb5e7d7450bec
        "the quick brown fox jumps over the lazy dog",
        // 18e8d559417db8a93707c11b11bb90b56638049a5994006ed4b2705e4d86587f
        "the quick brown fox jumps over the lazy dog.",
        // 71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73
        "abcdefghijklmnopqrstuvwxyz",
        // 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
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