#include "Signer_Dilithium.h"
#include <stdexcept>
#include <sodium.h>

/*
 * Post-quantum Dilithium2 implementation via liboqs’s OQS_SIG API.
 */

Signer_Dilithium::Signer_Dilithium() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }

    // Create a Dilithium2 context
    _oqs = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (_oqs == nullptr) {
        throw std::runtime_error("OQS_SIG_new(Dilithium2) failed");
    }

    keygen();
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

// Generate a fresh Dilithium2 keypair
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
