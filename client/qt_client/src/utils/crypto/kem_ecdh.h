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
 * C++ Concepts:
 *  - Inheritance: implements abstract Kem interface
 *  - Virtual Destructor: inherited from CryptoBase
 *  - Encapsulation: hides libsodium details
 *  - Copy vs. Move: disable copy, allow move if desired
 */
class Kem_Ecdh : public Kem {
public:
    Kem_Ecdh();
    ~Kem_Ecdh() override;

    // Copy operations throw exceptions to avoid unintentional key duplication
    // Allowing copy increases attack surface
    Kem_Ecdh(const Kem_Ecdh&);
    Kem_Ecdh& operator=(const Kem_Ecdh&);

    // Move operations are permitted
    Kem_Ecdh(Kem_Ecdh&&) noexcept = default;
    Kem_Ecdh& operator=(Kem_Ecdh&&) noexcept = default;

    // Inherited functions from the Kem interface
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    Encaps encap(const std::vector<uint8_t>& peerPk) const override;
    std::vector<uint8_t> decap(const std::vector<uint8_t>& ciphertext) const override;

private:
    // Raw key storage
    uint8_t _sk[crypto_scalarmult_SCALARBYTES];
    uint8_t _pk[crypto_scalarmult_BYTES];
};
