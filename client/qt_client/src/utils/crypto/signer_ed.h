#pragma once
#include "Signer.h"
#include <sodium.h>
#include <vector>
#include <cstdint>

/**
 * Signer_Ed
 *
 * Pre-quantum Ed25519 implementation using libsodium’s crypto_sign API.
 *
 * Chris C++ Requirements:
 * - Pointers and Arrays
 */
class Signer_Ed : public Signer {
public:
    Signer_Ed();
    ~Signer_Ed() override;

    // forbid copying, allow moving
    Signer_Ed(const Signer_Ed&);
    Signer_Ed& operator=(const Signer_Ed&);
    Signer_Ed(Signer_Ed&&) noexcept = default;
    Signer_Ed& operator=(Signer_Ed&&) noexcept = default;

    // Inherited Signer interface
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const override;
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& signature) const override;

    // ← NEW: load an existing Ed25519 private key (64 bytes)
    void loadPrivateKey(const uint8_t* rawSk, size_t len);

    // ← NEW: get a pointer to the 64‐byte secret key buffer
    const unsigned char* getSecretKeyBuffer() const { return _sk; }

private:
    uint8_t _sk[crypto_sign_SECRETKEYBYTES];   // 64 bytes
    uint8_t _pk[crypto_sign_PUBLICKEYBYTES];   // 32 bytes
};
