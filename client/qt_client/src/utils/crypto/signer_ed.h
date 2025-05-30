#pragma once
#include "Signer.h"
#include <sodium.h>
#include <vector>
#include <cstdint>

/**
 * Signer_Ed
 *
 * Pre-quantum digital signature algorithm using Ed25519 (Edwards-curve).
 *
 *
 * C++ Concepts:
 *  - Inheritance & Polymorphism: implements Signer interface
 *  - Virtual Destructor: via CryptoBase
 *  - Resource Management: zeroizing secret on destruction
 *  - Rule of Five: delete copy, default move
 */
class Signer_Ed : public Signer {
public:
    Signer_Ed();
    ~Signer_Ed() override;

    // Copy operations throw exceptions to avoid unintentional key duplication
    // Allowing copy increases attack surface
    Signer_Ed(const Signer_Ed&);
    Signer_Ed& operator=(const Signer_Ed&);

    // Allow moving
    Signer_Ed(Signer_Ed&&) noexcept = default;
    Signer_Ed& operator=(Signer_Ed&&) noexcept = default;

    // Inherited Signer interface
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const override;
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& signature) const override;

private:
    uint8_t _sk[crypto_sign_SECRETKEYBYTES];
    uint8_t _pk[crypto_sign_PUBLICKEYBYTES];
};
