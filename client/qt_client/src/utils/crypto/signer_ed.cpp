#include "Signer_Ed.h"
#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include <QDebug>

Signer_Ed::Signer_Ed() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
    // zero‐initialize (not strictly necessary, but safe)
    std::memset(_sk, 0, sizeof _sk);
    std::memset(_pk, 0, sizeof _pk);
}

Signer_Ed::~Signer_Ed() {
    // Zero out both secret and public key on destruction
    sodium_memzero(_sk, sizeof _sk);
    sodium_memzero(_pk, sizeof _pk);
}

void Signer_Ed::keygen() {
    // Generates 32‐byte public key in _pk and 64‐byte secret key in _sk
    if (crypto_sign_keypair(_pk, _sk) != 0) {
        throw std::runtime_error("crypto_sign_keypair failed");
    }
}

std::vector<uint8_t> Signer_Ed::pub() const {
    // Return a copy of the 32‐byte public key
    return std::vector<uint8_t>(_pk, _pk + crypto_sign_PUBLICKEYBYTES);
}

std::vector<uint8_t> Signer_Ed::sign(const std::vector<uint8_t>& msg) const {
    std::vector<uint8_t> sig(crypto_sign_BYTES);
    unsigned long long siglen = 0;
    if (crypto_sign_detached(
            sig.data(), &siglen,
            msg.data(), msg.size(),
            _sk) != 0) {
        throw std::runtime_error("crypto_sign_detached failed");
    }
    sig.resize(siglen);
    return sig;
}

bool Signer_Ed::verify(const std::vector<uint8_t>& msg,
                       const std::vector<uint8_t>& signature) const {
    if (signature.size() != crypto_sign_BYTES) {
        return false;
    }
    return (crypto_sign_verify_detached(
                signature.data(),
                msg.data(), msg.size(),
                _pk) == 0);
}

void Signer_Ed::loadPrivateKey(const uint8_t* rawSk, size_t len) {
    if (len != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error(
            "Signer_Ed::loadPrivateKey: expected exactly "
            + std::to_string(crypto_sign_SECRETKEYBYTES)
            + " bytes, but got " + std::to_string(len) + " bytes.");
    }
    // Copy the 64 bytes (seed∥public)
    std::memcpy(this->_sk, rawSk, crypto_sign_SECRETKEYBYTES);

    // Re-derive the public key into _pk
    if (crypto_sign_ed25519_sk_to_pk(this->_pk, rawSk) != 0) {
        throw std::runtime_error(
            "Signer_Ed::loadPrivateKey: crypto_sign_ed25519_sk_to_pk failed"
            );
    }
}
