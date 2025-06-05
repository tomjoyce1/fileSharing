#pragma once
#include "kem.h"
#include <sodium.h>
#include <vector>
#include <cstdint>

/**
 * Kem_Ecdh
 *
 * Pre-quantum Key Encapsulation Mechanism via X25519 (Curve25519 DH).
 * Used to share File Encryption Keys
 *
 * Chris C++ Requirements:
 * - Types of Inheritance: Implement and demonstrate at least one form of inheritance (single, multiple) by creating derived classes from base classes.
 * - Constructor and Destructor Behavior in Inheritance
 */
class Kem_Ecdh : public Kem {
public:
    Kem_Ecdh();
    ~Kem_Ecdh() override;

    // forbid copy, allow move
    Kem_Ecdh(const Kem_Ecdh&);
    Kem_Ecdh& operator=(const Kem_Ecdh&);
    Kem_Ecdh(Kem_Ecdh&&) noexcept = default;
    Kem_Ecdh& operator=(Kem_Ecdh&&) noexcept = default;

    // Inherited functions from the Kem interface
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    Encaps encap(const std::vector<uint8_t>& peerPk) const override;
    std::vector<uint8_t> decap(const std::vector<uint8_t>& ciphertext) const override;

    // expose X25519 secret‐key as a 32‐byte vector
    std::vector<uint8_t> getSecretKey() const {
        return std::vector<uint8_t>(_sk, _sk + crypto_scalarmult_SCALARBYTES);
    }

private:
    // Raw key storage (32‐byte scalar, 32‐byte public)
    uint8_t _sk[crypto_scalarmult_SCALARBYTES];
    uint8_t _pk[crypto_scalarmult_BYTES];
};
