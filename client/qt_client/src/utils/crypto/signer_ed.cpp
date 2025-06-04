#include "Signer_Ed.h"

#include <stdexcept>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/err.h>   // ← Must include this for ERR_get_error, ERR_error_string_n
#include <cstring>
#include <QDebug>          // Only if you want to debug via qDebug()

/*
 * Pre‐quantum Ed25519 implementation using libsodium’s crypto_sign API.
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
    if (_evpPkey) {
        EVP_PKEY_free(_evpPkey);
        _evpPkey = nullptr;
    }
}

// Generate a fresh Ed25519 keypair (32‐byte pub, 64‐byte sk=seed||pub)
void Signer_Ed::keygen() {
    if (crypto_sign_keypair(_pk, _sk) != 0) {
        throw std::runtime_error("crypto_sign_keypair failed");
    }
}

std::vector<uint8_t> Signer_Ed::pub() const {
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
    //────────────────────────────────────────────────────────────────────────
    // 1) Expect exactly 64 bytes (libsodium’s “seed ∥ pub” format)
    //────────────────────────────────────────────────────────────────────────
    if (len != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error(
            "Signer_Ed::loadPrivateKey: expected exactly "
            + std::to_string(crypto_sign_SECRETKEYBYTES)
            + " bytes, but got " + std::to_string(len) + " bytes."
            );
    }

    //────────────────────────────────────────────────────────────────────────
    // 2) Copy the entire 64 bytes into our internal _sk[], so libsodium can still sign:
    //────────────────────────────────────────────────────────────────────────
    std::memcpy(this->_sk, rawSk, crypto_sign_SECRETKEYBYTES);

    //────────────────────────────────────────────────────────────────────────
    // 3) Derive the 32‐byte Ed25519 public key from that 64‐byte secret:
    //
    //    Calling crypto_sign_ed25519_sk_to_pk always recomputes “pub” from “seed”.
    //    This ensures that—even if the last 32 bytes of rawSk were corrupted—the
    //    public key is reconstructed correctly from seed[0..31].
    //────────────────────────────────────────────────────────────────────────
    if (crypto_sign_ed25519_sk_to_pk(this->_pk, rawSk) != 0) {
        throw std::runtime_error(
            "Signer_Ed::loadPrivateKey: crypto_sign_ed25519_sk_to_pk failed"
            );
    }

    // (OPTIONAL DEBUG: print _pk in hex to verify it’s non‐zero and correct)
#if 0
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++) {
            oss << std::setw(2) << static_cast<int>(_pk[i]);
        }
        qDebug() << "[Signer_Ed] derived pubKey =" << QString::fromStdString(oss.str());
    }
#endif

    //────────────────────────────────────────────────────────────────────────
    // 4) Build an OpenSSL EVP_PKEY from those 32 bytes (_pk).  If OpenSSL
    //    finds anything wrong with those 32 bytes, EVP_PKEY_new_raw_public_key will fail.
    //────────────────────────────────────────────────────────────────────────
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        this->_pk,
        crypto_sign_PUBLICKEYBYTES
        );
    if (!pkey) {
        // If OpenSSL failed, pull its error queue to see why:
        unsigned long errCode = ERR_get_error();
        char errMsg[256] = {0};
        ERR_error_string_n(errCode, errMsg, sizeof(errMsg));
        throw std::runtime_error(
            std::string("Signer_Ed::loadPrivateKey: EVP_PKEY_new_raw_public_key failed: ")
            + errMsg
            );
    }

    //────────────────────────────────────────────────────────────────────────
    // 5) Free any previous _evpPkey, then store the new one:
    //────────────────────────────────────────────────────────────────────────
    if (this->_evpPkey) {
        EVP_PKEY_free(this->_evpPkey);
    }
    this->_evpPkey = pkey;
}
