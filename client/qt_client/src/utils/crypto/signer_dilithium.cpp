#include "Signer_Dilithium.h"
#include <stdexcept>
#include <sodium.h>

/*
 * Post-quantum Dilithium5 (ML-DSA87) implementation via liboqs’s OQS_SIG API.
 */

Signer_Dilithium::Signer_Dilithium() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
    _oqs = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (_oqs == nullptr) {
        throw std::runtime_error("OQS_SIG_new(Dilithium5) failed");
    }
    // Allocate zero-length vectors; keygen() will resize them
    _pk.clear();
    _sk.clear();
}

Signer_Dilithium::~Signer_Dilithium() {
    // Wipe secret key material
    if (!_sk.empty()) {
        sodium_memzero(_sk.data(), _sk.size());
    }
    // Free the liboqs context
    OQS_SIG_free(_oqs);
}

Signer_Dilithium::Signer_Dilithium(const Signer_Dilithium&) {
    throw std::logic_error("Signer_Dilithium copy-construction is forbidden");
}

Signer_Dilithium& Signer_Dilithium::operator=(const Signer_Dilithium&) {
    throw std::logic_error("Signer_Dilithium copy-assignment is forbidden");
}

// Generate a fresh Dilithium5 keypair
void Signer_Dilithium::keygen() {
    // Resize to library‐specified lengths
    _pk.resize(_oqs->length_public_key);
    _sk.resize(_oqs->length_secret_key);

    if (OQS_SIG_keypair(
            _oqs,
            _pk.data(),
            _sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("OQS_SIG_keypair failed");
    }
}

// Return the public key bytes
std::vector<uint8_t> Signer_Dilithium::pub() const {
    return _pk;
}

// Sign a message with Dilithium
std::vector<uint8_t> Signer_Dilithium::sign(const std::vector<uint8_t>& msg) const {
    std::vector<uint8_t> sig(_oqs->length_signature);
    size_t siglen = 0;

    if (OQS_SIG_sign(
            _oqs,
            sig.data(), &siglen,
            msg.data(), msg.size(),
            _sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("OQS_SIG_sign failed");
    }
    sig.resize(siglen);
    return sig;
}

// Verify a Dilithium signature
bool Signer_Dilithium::verify(const std::vector<uint8_t>& msg,
                              const std::vector<uint8_t>& signature) const {
    if (signature.size() != _oqs->length_signature) {
        return false;
    }
    // Returns OQS_SUCCESS (0) on valid, non-zero on failure
    return OQS_SIG_verify(
               _oqs,
               msg.data(), msg.size(),
               signature.data(), signature.size(),
               _pk.data()) == OQS_SUCCESS;
}

// ← NEW: load an existing Dilithium secret key into _sk
void Signer_Dilithium::loadPrivateKey(const uint8_t* rawSk, size_t len) {
    if (len != static_cast<size_t>(_oqs->length_secret_key)) {
        throw std::runtime_error("Signer_Dilithium::loadPrivateKey: wrong length");
    }
    // Resize _sk so that _sk.data() is valid:
    _sk.resize(len);
    memcpy(_sk.data(), rawSk, len);

}

