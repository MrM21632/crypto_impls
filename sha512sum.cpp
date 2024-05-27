#include "sha512.hpp"
#include <iostream>


int main() {
    // TODO: Currently fails for non-empty messages, need to investigate
    std::vector<std::string> test_messages = {
        // cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
        "",
        // 1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75
        "a",
        // ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
        "abc",
        // 107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c
        "message digest",
        // 801b90d850f51736249cb33df75e17918c2233d7a083cb9d27561160ae15f1e2cc2c97531fcdaa8426c654ba9c7c3a4b7d97ba770d09f0d839bff3047b2f5ce2
        "the quick brown fox jumps over the lazy dog",
        // 20e750d653399e0b7cda086b296f3b0370784e9b9eeb5e137983af7a650d1c4000829b0d5d23f7e99680dd1f834998145421b621239e4b5878b01030db3e8003
        "the quick brown fox jumps over the lazy dog.",
        // 4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1
        "abcdefghijklmnopqrstuvwxyz",
        // 8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    };

    for (std::string message : test_messages) {
        SHA512Impl hash;
        std::array<uint64_t, 8> result = hash.digest_message(message);

        std::cout << message << ": ";
        for (const auto& val : result) {
            std::cout << std::hex << val;
        }
        std::cout << std::endl;
    }
}