#include <cstdint>
#include <iostream>
#include <array>
#include <vector>


std::array<uint8_t, 8> expand_length(uint64_t length) {
    std::array<uint8_t, 8> result;
    for (int i = 7; i >= 0; --i) {
        result[7 - i] = (length >> (8 * i)) & 0xff;
    }

    return result;
}


// Test file I wrote to verify length encoding for SHA-2.
int main() {
    std::vector<uint64_t> test_lengths = {
        0,
        8,
        24,
        112,
        344,
        352,
        208,
        448,
    };

    for (auto& length : test_lengths) {
        std::array<uint8_t, 8> encoded = expand_length(length);
        for (std::array<uint8_t, 8>::iterator it = encoded.begin(); it != encoded.end(); ++it) {
            std::cout << std::hex << (int) *it << ' ';
        }
        std::cout << std::endl;
    }
}