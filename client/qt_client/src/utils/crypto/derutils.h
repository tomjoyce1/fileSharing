#pragma once
#include <vector>
#include <cstddef>
#include <openssl/evp.h>

/**
 * Helper functions for wrapping raw 32-byte public keys into SPKI-DER blobs.
 */
namespace der {


    std::vector<uint8_t> toSpkiDer(int openssl_nid, const uint8_t* raw, std::size_t rawLen);

    inline std::vector<uint8_t> x25519(const std::vector<uint8_t>& raw32) {
        return toSpkiDer(EVP_PKEY_X25519, raw32.data(), raw32.size());
    }

    inline std::vector<uint8_t> ed25519(const std::vector<uint8_t>& raw32) {
        return toSpkiDer(EVP_PKEY_ED25519, raw32.data(), raw32.size());
    }

}
