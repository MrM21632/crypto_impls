#ifndef MRM21632_MD5_HPP_
#define MRM21632_MD5_HPP_

#include <cstdint>
#include <array>
#include <string>
#include <vector>


// Baseline implementation of the MD5 hash function.
class MD5 {
private:
    std::array<uint32_t, 4> init_vector;  // Initialization vector; used to reset state for each hash.
    std::array<uint32_t, 4> state;  // Hash state

    // F and G(b, c, d)
    uint32_t choose(uint32_t, uint32_t, uint32_t);
    // H(b, c, d)
    uint32_t h(uint32_t, uint32_t, uint32_t);
    // I(b, c, d)
    uint32_t i(uint32_t, uint32_t, uint32_t);

    // Pad the string into a list of bytes.
    std::vector<uint8_t> pad_message(std::string);
    // Execute a compression round. Accepts a 512-bit chunk of the padded message as input.
    void compress(std::array<uint8_t, 64>);
public:
    MD5(std::array<uint32_t, 4>);
    std::array<uint32_t, 4> digest_message(std::string);
};


// Implementation of MD5.
class MD5Impl : public MD5 {
public:
    MD5Impl();
};

#endif  // MRM21632_MD5_HPP_