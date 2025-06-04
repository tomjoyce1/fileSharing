#pragma once
#include <vector>
#include <cstring>
#include <stdexcept>
#include <sodium.h>

/*
 * Pre-quantum Ed25519 implementation using libsodium’s crypto_sign API.
 */
class Signer_Ed {
public:
    Signer_Ed();
    ~Signer_Ed();

    // Generate a fresh Ed25519 keypair (32-byte pub, 64-byte sk = seed∥pub)
    void keygen();

    // Sign a message under the loaded secret key
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const;

    // Verify a signature against the loaded public key
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& signature) const;

    // Load an existing 64-byte Ed25519 secret key (seed∥pub)
    void loadPrivateKey(const uint8_t* rawSk, size_t len);

    // Return the 32‐byte public key
    std::vector<uint8_t> pub() const;

    const uint8_t* getSecretKeyBuffer() const {
        return _sk;
    }

private:
    uint8_t _sk[crypto_sign_SECRETKEYBYTES];    // 64 bytes: seed∥public
    uint8_t _pk[crypto_sign_PUBLICKEYBYTES];    // 32 bytes: public key
};
