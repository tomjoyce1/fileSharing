#include "Kem_Ecdh.h"
#include <stdexcept>

Kem_Ecdh::Kem_Ecdh() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
    // Immediately generate keypair
    keygen();
}

Kem_Ecdh::~Kem_Ecdh() {
    sodium_memzero(_sk, sizeof _sk);
    sodium_memzero(_pk, sizeof _pk);
}

Kem_Ecdh::Kem_Ecdh(const Kem_Ecdh&) {
    throw std::logic_error("Kem_Ecdh copy-construction is forbidden");
}

Kem_Ecdh& Kem_Ecdh::operator=(const Kem_Ecdh&) {
    throw std::logic_error("Kem_Ecdh copy-assignment is forbidden");
}

// produce a fresh X25519 keypair
void Kem_Ecdh::keygen() {
    // rand private scalar
    randombytes_buf(_sk, sizeof _sk);
    // pub = scalar * curve's basepoint
    crypto_scalarmult_base(_pk, _sk);
}

// return the 32-byte public key
std::vector<uint8_t> Kem_Ecdh::pub() const {
    return std::vector<uint8_t>(_pk, _pk + crypto_scalarmult_BYTES);
}

// generate ephemeral keypair, compute shared secret
Encaps Kem_Ecdh::encap(const std::vector<uint8_t>& peerPk) const {
    if (peerPk.size() != crypto_scalarmult_BYTES) {
        throw std::invalid_argument("peer public key must be 32 bytes");
    }

    // ephemeral scalar & pubkey
    uint8_t esk[crypto_scalarmult_SCALARBYTES];
    uint8_t epk[crypto_scalarmult_BYTES];
    randombytes_buf(esk, sizeof esk);
    crypto_scalarmult_base(epk, esk);

    // DH: shared = esk * peerPk
    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    int rc = crypto_scalarmult(shared.data(), esk, peerPk.data());
    if (rc != 0) {
        throw std::runtime_error("Kem_Ecdh::encap: crypto_scalarmult failed");
    }

    return Encaps{
        std::vector<uint8_t>(epk, epk + sizeof epk),
        std::move(shared)
    };
}

// compute shared secret from peer’s ephemeral pubkey
std::vector<uint8_t> Kem_Ecdh::decap(const std::vector<uint8_t>& ciphertext) const {
    if (ciphertext.size() != crypto_scalarmult_BYTES) {
        throw std::invalid_argument("ciphertext must be 32 bytes");
    }
    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    int rc = crypto_scalarmult(shared.data(), _sk, ciphertext.data());
    if (rc != 0) {
        throw std::runtime_error("Kem_Ecdh::encap: crypto_scalarmult failed");
    }

    return shared;
}
