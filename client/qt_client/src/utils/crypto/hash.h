#pragma once
#include <vector>
#include <cstdint>

#include <openssl/evp.h>

/**
 * Takes an arbitrary-length byte string as input and produces a fixed-length digest
 */
namespace Hash {
    /**
     * Compute the SHA-256 digest of the given byte buffer.
     *
     * @param data  A byte buffer (std::vector<uint8_t>), passed by const reference.
     * @return      A 32-byte vector containing the SHA-256 digest.
     */
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

    /**
     * Overload: same one-shot SHA-256, but takes a raw pointer and length.
     *
     * @param dataPtr  Pointer to the first byte.
     * @param len      Number of bytes to hash.
     * @return         A 32-byte vector containing the SHA-256 digest.
     */
    std::vector<uint8_t> sha256(const uint8_t* dataPtr, size_t len);
}
