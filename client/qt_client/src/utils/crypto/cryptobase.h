#pragma once
#include <cstddef>

/*
 * Defines the abstract base class that is inherited by all crypto classes
 *
 * C++ Chris Concepts:
 * - Pure Virtual Functions and Abstract Classes
 * - Virtual Destructors
 */

class CryptoBase {
public:
    // using default instructs the compiler call the destructors of the class members
    virtual ~CryptoBase() = default;
protected:
    static constexpr std::size_t NONCE_LEN = 16;
};
