#include "DerUtils.h"

#include <openssl/evp.h>
#include <openssl/x509.h>   // for i2d_PUBKEY, d2i_PUBKEY
#include <stdexcept>

namespace der {

std::vector<uint8_t> toSpkiDer(int nid, const uint8_t* raw, std::size_t rawLen) {
    // Create an EVP_PKEY from the raw bytes
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(nid, nullptr, raw, rawLen);
    if (!pkey) {
        throw std::runtime_error("der::toSpkiDer: EVP_PKEY_new_raw_public_key failed");
    }

    // Ask OpenSSL how many DER bytes we need
    int derLen = i2d_PUBKEY(pkey, nullptr);
    if (derLen <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("der::toSpkiDer: i2d_PUBKEY returned <= 0");
    }

    std::vector<uint8_t> der(derLen);
    unsigned char* outPtr = der.data();
    i2d_PUBKEY(pkey, &outPtr);

    EVP_PKEY_free(pkey);
    return der;
}

std::vector<uint8_t> parseSpkiDer(int nid, const uint8_t* derBytes, std::size_t derLen) {
    // Reconstruct an EVP_PKEY from the DER blob
    const unsigned char* p = derBytes;
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, derLen);
    if (!pkey) {
        throw std::runtime_error("der::parseSpkiDer: d2i_PUBKEY failed");
    }

    // Now fetch the raw public key
    size_t rawLen = 0;
    if (!EVP_PKEY_get_raw_public_key(pkey, nullptr, &rawLen)) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("der::parseSpkiDer: EVP_PKEY_get_raw_public_key(0) failed");
    }

    std::vector<uint8_t> raw(rawLen);
    if (!EVP_PKEY_get_raw_public_key(pkey, raw.data(), &rawLen)) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("der::parseSpkiDer: EVP_PKEY_get_raw_public_key(data) failed");
    }

    EVP_PKEY_free(pkey);
    return raw;
}



} // namespace der
