#ifndef MRM21632_SHA512_HPP_
#define MRM21632_SHA512_HPP_

#include <array>
#include <cstdint>
#include <string>
#include <vector>


// Baseline implementation of the SHA-512 and derived hash functions.
class SHA512 {
private:
    std::array<uint64_t, 8> state;  // Initialization vectors, and final state

    // Ch(e, f, g)
    uint64_t choose(uint64_t, uint64_t, uint64_t);
    // Maj(a, b, c)
    uint64_t major(uint64_t, uint64_t, uint64_t);

    // Σ0(a)
    uint64_t sum0(uint64_t);
    // Σ1(e)
    uint64_t sum1(uint64_t);

    // σ0(w)
    uint64_t sigma0(uint64_t);
    // σ1(w)
    uint64_t sigma1(uint64_t);

    // Pad the string into a list of bytes.
    std::string pad_message(std::string);
    // Execute a compression round.
    void compress(std::array<uint8_t, 128>);
public:
    SHA512(std::array<uint64_t, 8>);
    std::array<uint64_t, 8> digest_message(std::string);
};


// Implementation of SHA-512.
class SHA512Impl : public SHA512 {
public:
    SHA512Impl();
};

// Implementation of SHA-384.
class SHA384Impl : public SHA512 {
public:
    SHA384Impl();
};

// Implementation of SHA-512/224.
class SHA512t224Impl : public SHA512 {
public:
    SHA512t224Impl();
};

// Implementation of SHA-512/256.
class SHA512t256Impl : public SHA512 {
public:
    SHA512t256Impl();
};

#endif  // MRM21632_SHA512_HPP_
