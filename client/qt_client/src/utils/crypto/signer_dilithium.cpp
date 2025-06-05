#include "Signer_Dilithium.h"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

Signer_Dilithium::Signer_Dilithium() {
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");

    _oqs = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);     // ← THE ONLY REAL CHANGE
    if (!_oqs)
        throw std::runtime_error("OQS_SIG_new(ml_dsa_87) failed");
}

Signer_Dilithium::~Signer_Dilithium() {
    if (!_sk.empty()) sodium_memzero(_sk.data(), _sk.size());
    OQS_SIG_free(_oqs);
}

void Signer_Dilithium::keygen() {
    _pk.resize(_oqs->length_public_key);   // 2 592 B
    _sk.resize(_oqs->length_secret_key);   // 4 896 B

    if (OQS_SIG_keypair(_oqs, _pk.data(), _sk.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_SIG_keypair failed");
}

std::vector<uint8_t> Signer_Dilithium::pub() const { return _pk; }

std::vector<uint8_t>
Signer_Dilithium::sign(const std::vector<uint8_t>& msg) const {
    std::vector<uint8_t> sig(_oqs->length_signature);   // 4 595 B
    size_t siglen = 0;

    if (OQS_SIG_sign(_oqs, sig.data(), &siglen,
                     msg.data(), msg.size(),
                     _sk.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_SIG_sign failed");

    sig.resize(siglen);
    return sig;
}

bool Signer_Dilithium::verify(const std::vector<uint8_t>& msg,
                              const std::vector<uint8_t>& sig) const {
    if (sig.size() != _oqs->length_signature) return false;

    return OQS_SIG_verify(_oqs,
                          msg.data(), msg.size(),
                          sig.data(), sig.size(),
                          _pk.data()) == OQS_SUCCESS;
}

// import existing secret-key
void Signer_Dilithium::loadPrivateKey(const uint8_t* rawSk, size_t len) {
    if (len != _oqs->length_secret_key)
        throw std::runtime_error("Signer_Dilithium::loadPrivateKey: wrong len");

    _sk.assign(rawSk, rawSk + len);
}

void Signer_Dilithium::loadPublicKey(const uint8_t* rawPk, size_t len)
{
    if (len != _oqs->length_public_key)
        throw std::runtime_error("Signer_Dilithium::loadPublicKey wrong length");

    _pk.assign(rawPk, rawPk + len);
}
