#pragma once
#include "Signer.h"
#include <oqs/oqs.h>
#include <vector>
#include <cstdint>

/**
 * Signer_Dilithium
 *
 * Post-quantum digital signature using CRYSTALS-Dilithium2 via liboqs.
 *
 *
 * C++ Concepts:
 *  - Inheritance & Polymorphism
 *  - RAII: allocate + free OQS_SIG context
 *  - Rule of Five: delete copy, default move
 *  - Secure Memory: wipe secret key on destruction
 */
class Signer_Dilithium : public Signer {
public:
    Signer_Dilithium();
    ~Signer_Dilithium() override;

    // Disallow copying
    Signer_Dilithium(const Signer_Dilithium&);
    Signer_Dilithium& operator=(const Signer_Dilithium&);

    // Allow moving
    Signer_Dilithium(Signer_Dilithium&&) noexcept = default;
    Signer_Dilithium& operator=(Signer_Dilithium&&) noexcept = default;

    // Inherited Signer interface
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const override;
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& signature) const override;

private:
    OQS_SIG * _oqs;                   // liboqs signature context
    std::vector<uint8_t> _pk;         // public key bytes
    std::vector<uint8_t> _sk;         // secret key bytes
};
