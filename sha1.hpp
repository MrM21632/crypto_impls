#ifndef MRM21632_SHA1_HPP_
#define MRM21632_SHA1_HPP_

#include <cstdint>
#include <array>
#include <string>
#include <vector>


// Baseline implementation of the SHA-1 hash function.
class SHA1 {
private:
    std::array<uint32_t, 5> init_vector;  // Initialization vector; used to reset state for each hash.
    std::array<uint32_t, 5> state;  // Hash state

    // Ch(b, c, d)
    uint32_t choose(uint32_t, uint32_t, uint32_t);
    // Maj(b, c, d)
    uint32_t major(uint32_t, uint32_t, uint32_t);
    // Parity(b, c, d)
    uint32_t parity(uint32_t, uint32_t, uint32_t);

    // Pad the string into a list of bytes.
    std::vector<uint8_t> pad_message(std::string);
    // Execute a compression round. Accepts a 512-bit chunk of the padded message as input.
    void compress(std::array<uint8_t, 64>);
public:
    SHA1(std::array<uint32_t, 5>);
    std::array<uint32_t, 5> digest_message(std::string);
};


// Implementation of SHA-1.
class SHA1Impl : public SHA1 {
public:
    SHA1Impl();
};

#endif  // MRM21632_SHA1_HPP_