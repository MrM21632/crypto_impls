# Cryptographic Hash Implementations

This repository contains a test implementation of several families of cryptographic hashes. Currently, the following are fully implemented and verified:
- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-512/224
- SHA-512/256

Implementations for the following will also be provided down the line:
- RIPEMD
- BLAKE2b

Other goals for this repository:
- Platform-agnostic Makefile for building the executables
- Write proper executables for the checksums, behaving like those in coreutils
- Maybe add other checksum implementations, including the following:
  - Whirlpool
  - SHA-3 (not likely, this honestly seems pretty complicated to implement)
- Maybe add some cipher implementations? The following seem worth considering:
  - AES
  - DES
  - RC4
  - TEA, maybe a variant like XXTEA

Bear in mind: since this is a test implementation, there are no guarantees that this is a viable package for production systems. Consider this a reference for the algorithms, and use at your own risk.