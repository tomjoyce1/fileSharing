#pragma once
#include "cryptobase.h"
#include <vector>
#include <cstdint>

/**
 * Encaps holds the two outputs of a KEM:
 *  - ciphertext: the encapsulation blob to send to the peer
 *  - sharedSecret: the recovered secret on the sender side
 */
struct Encaps {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> sharedSecret;
};

/**
 * Defines the KEM (Key Encapulation Mechanism) interface
 *
 * C++ Chris Concepts:
 * - Inheritence
 * - Virtual Destructors
 */
class Kem : public CryptoBase {
public:
    virtual ~Kem() = default;

    /// Generates a fresh keypair
    virtual void keygen() = 0;

    /// @return the public-key bytes corresponding to that keypair
    virtual std::vector<uint8_t> pub() const = 0;

    /**
     * Encapsulates a random secret under the recipient’s public key
     * @param peerPk: the recipient’s public key bytes
     * @return: an Encaps struct
     */
    virtual Encaps encap(const std::vector<uint8_t>& peerPk) const = 0;

    /**
     * Decapsulates a secret from ciphertext using the local private key
     *
     * @param ciphertext: ciphertext bytes produced by encap()
     * @return: Shared secret bytes derived from the ciphertext
     */
    virtual std::vector<uint8_t> decap(const std::vector<uint8_t>& ciphertext) const = 0;
};
