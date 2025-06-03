#include "Signer_Ed.h"
#include <stdexcept>
#include <sodium.h>

/*
 * Pre-quantum Ed25519 implementation using libsodium’s crypto_sign API.
 */

Signer_Ed::Signer_Ed() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
}

Signer_Ed::~Signer_Ed() {
    // Securely erase both secret and public keys
    sodium_memzero(_sk, sizeof _sk);
    sodium_memzero(_pk, sizeof _pk);
}

Signer_Ed::Signer_Ed(const Signer_Ed&) {
    throw std::logic_error("Signer_Ed copy-construction is forbidden");
}

Signer_Ed& Signer_Ed::operator=(const Signer_Ed&) {
    throw std::logic_error("Signer_Ed copy-assignment is forbidden");
}

// Generate a fresh Ed25519 keypair
void Signer_Ed::keygen() {
    if (crypto_sign_keypair(_pk, _sk) != 0) {
        throw std::runtime_error("crypto_sign_keypair failed");
    }
}

// Return the public key bytes
std::vector<uint8_t> Signer_Ed::pub() const {
    return std::vector<uint8_t>(_pk, _pk + crypto_sign_PUBLICKEYBYTES);
}

// Produce a detached Ed25519 signature
std::vector<uint8_t> Signer_Ed::sign(const std::vector<uint8_t>& msg) const {
    std::vector<uint8_t> sig(crypto_sign_BYTES);
    unsigned long long siglen = 0;
    if (crypto_sign_detached(
            sig.data(), &siglen,
            msg.data(), msg.size(),
            _sk) != 0) {
        throw std::runtime_error("crypto_sign_detached failed");
    }
    // siglen == crypto_sign_BYTES (64)
    sig.resize(siglen);
    return sig;
}

// Verify a detached Ed25519 signature
bool Signer_Ed::verify(const std::vector<uint8_t>& msg,
                       const std::vector<uint8_t>& signature) const {
    if (signature.size() != crypto_sign_BYTES) {
        return false;
    }
    // Returns 0 on success, -1 on failure
    return crypto_sign_verify_detached(
               signature.data(),
               msg.data(), msg.size(),
               _pk) == 0;
}

// ← NEW: load an existing Ed25519 secret key
void Signer_Ed::loadPrivateKey(const uint8_t* rawSk, size_t len) {
    if (len != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error("Signer_Ed::loadPrivateKey: wrong length");
    }
    memcpy(_sk, rawSk, crypto_sign_SECRETKEYBYTES);
    // Recompute public key from secret key:
    // libsodium lets you do:
    crypto_sign_ed25519_sk_to_pk(_pk, _sk);
}
