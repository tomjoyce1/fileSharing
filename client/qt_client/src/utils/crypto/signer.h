#pragma once
#include "cryptobase.h"
#include <vector>
#include <cstdint>

/**
 * Defines the Signer interface
 *
 * C++ Concepts demonstrated:
 *  - Inheritance       (Signer inherits from CryptoBase)
 *  - Virtual Destructor
 *  - Pure Virtuals     (abstract base class)
 *  - User-defined types (Signature struct)
 */
class Signer : public CryptoBase {
public:
    virtual ~Signer() = default;

    /// Generates a fresh keypair
    virtual void keygen() = 0;

    /// @return the public-key bytes corresponding to that keypair
    virtual std::vector<uint8_t> pub() const = 0;

    /**
     * Sign a message.
     * @param msg: the message to authenticate
     * @return: signature bytes
     */
    virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const = 0;

    /**
     * Verify a detached signature.
     * @param msg: the original message
     * @param signature: the signature bytes to check
     * @return: true if the signature is valid for this message
     */
    virtual bool verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& signature) const = 0;
};
