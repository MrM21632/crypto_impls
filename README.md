# Yet Another SHA-2 Implementation

This repository contains a test implementation of the SHA-2 family of cryptographic hashes. Currently, the following are fully implemented and verified:
- SHA-224
- SHA-256
- SHA-384
- SHA-512

Implementations for the following will also be provided down the line:
- SHA-512/224
- SHA-512/256

Other goals for this repository:
- Platform-agnostic Makefile for building the executables
- Write proper executables for the checksums, behaving like those in coreutils
- Maybe add other checksum implementations, including the following:
  - MD5
  - SHA-1
  - Whirlpool
  - RIPEMD
  - BLAKE2b
  - SHA-3 (not likely, this honestly seems pretty complicated to implement)

Bear in mind: since this is a test implementation, there are no guarantees that this is a viable package for production systems. Consider this a reference for the algorithms, and use at your own risk.