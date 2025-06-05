#pragma once
#include "Signer.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <vector>
#include <cstdint>

/**
 * Signer_Ed
 *
 * Ed25519 implementation using libsodium for sign/verify
 * and OpenSSL for any raw‐public‐key operations.
 */
class Signer_Ed : public Signer {
public:
    Signer_Ed();
    ~Signer_Ed() override;

    // forbid copying, allow moving
    Signer_Ed(const Signer_Ed&)            = delete;
    Signer_Ed& operator=(const Signer_Ed&) = delete;
    Signer_Ed(Signer_Ed&&) noexcept         = default;
    Signer_Ed& operator=(Signer_Ed&&) noexcept = default;

    // Signer interface:
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const override;
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& signature) const override;

    // ← NEW: load an existing 64‐byte Ed25519 secret (seed||pub).
    void loadPrivateKey(const uint8_t* rawSk, size_t len);
    void loadPublicKey (const uint8_t* rawPk, size_t len);

    // ← NEW (optional): expose the raw 64‐byte libsodium sk if needed
    const unsigned char* getSecretKeyBuffer() const { return _sk; }

private:
    uint8_t _sk[crypto_sign_SECRETKEYBYTES];   // 64 bytes: [ seed (32) || pub (32) ]
    uint8_t _pk[crypto_sign_PUBLICKEYBYTES];   // 32 bytes
    EVP_PKEY* _evpPkey = nullptr;              // OpenSSL handle for raw public key
};
