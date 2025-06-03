// CryptoBase.h
#pragma once
#include <cstddef>
#include <cstdint>

/**
 * Defines the abstract base class that is inherited by all crypto classes
 *
 * C++ Concepts Illustrated:
 * - Pure Virtual Functions and Abstract Classes
 * - Virtual Destructors
 * - Access Specifiers
 * - Use of protected Members in Inheritance
 * - Pointers: Declaration, Initialization, and Dereferencing
 * - Pointer Arithmetic
 */
class CryptoBase {
public:
    virtual ~CryptoBase() = default;

protected:
    // 16 bytes used for IV/nonces (AES-CTR, etc.)
    static constexpr std::size_t NONCE_LEN = 16;

    // 32 bytes used for AES-256 keys (FEK/MEK)
    static constexpr std::size_t KEY_LEN = 32;

    /**
     * Zeroizes a raw buffer using pointer arithmetic.
     * Example of pointer arithmetic: *(ptr + i) = 0
     */
    static void zeroizeBuffer(uint8_t* ptr, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
            *(ptr + i) = 0;
        }
    }
};
