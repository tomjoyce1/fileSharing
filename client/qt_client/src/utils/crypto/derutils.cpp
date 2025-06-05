#include "DerUtils.h"
#include <openssl/x509.h>
#include <stdexcept>
#include "QDebug"

namespace {

std::vector<uint8_t> wrapSpki(int nid,
                              const uint8_t* raw,
                              std::size_t    rawLen)
{
    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_public_key(nid, nullptr, raw, rawLen);
    if (!pkey)
        throw std::runtime_error("EVP_PKEY_new_raw_public_key failed");

    int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("i2d_PUBKEY failed");
    }
    std::vector<uint8_t> out(len);
    uint8_t* p = out.data();
    if (i2d_PUBKEY(pkey, &p) != len) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("i2d_PUBKEY wrote wrong length");
    }
    EVP_PKEY_free(pkey);
    return out;
}

bool looksLikeSpki44(const uint8_t* buf, std::size_t len, int nid)
{
    if (len != 44) return false;
    const uint8_t* p = buf;
    EVP_PKEY* k = d2i_PUBKEY(nullptr, &p, len);
    if (!k) return false;
    int ok = (EVP_PKEY_base_id(k) == nid);
    EVP_PKEY_free(k);
    return ok;
}

}

namespace der {

bool isSpki(const uint8_t* buf, std::size_t len, int nid)
{
    return looksLikeSpki44(buf, len, nid);
}

std::vector<uint8_t> toSpkiOrPassthrough(int nid,
                                         const uint8_t* raw,
                                         std::size_t    rawLen)
{
    if (isSpki(raw, rawLen, nid))
        return {raw, raw + rawLen};          // already wrapped, keep as-is
    qDebug().nospace() << rawLen;
    if (rawLen != 32)
        throw std::runtime_error("unexpected key length (must be 32 or 44)");
    return wrapSpki(nid, raw, rawLen);       // wrap once
}

std::vector<uint8_t> parseX25519Spki(const std::vector<uint8_t>& der)
{
    if (!isSpki(der.data(), der.size(), EVP_PKEY_X25519))
        throw std::runtime_error("not a valid X25519 SPKI blob");

    const uint8_t* p = der.data();
    EVP_PKEY* k = d2i_PUBKEY(nullptr, &p, der.size());
    std::vector<uint8_t> raw(32);
    size_t len = raw.size();
    if (EVP_PKEY_get_raw_public_key(k, raw.data(), &len) != 1 || len != 32) {
        EVP_PKEY_free(k);
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    EVP_PKEY_free(k);
    return raw;
}

std::vector<uint8_t> parseEd25519Spki(const std::vector<uint8_t>& der)
{
    if (!isSpki(der.data(), der.size(), EVP_PKEY_ED25519))
        throw std::runtime_error("not a valid Ed25519 SPKI blob");

    const uint8_t* p = der.data();
    EVP_PKEY* k = d2i_PUBKEY(nullptr, &p, der.size());
    std::vector<uint8_t> raw(32);
    size_t len = raw.size();
    if (EVP_PKEY_get_raw_public_key(k, raw.data(), &len) != 1 || len != 32) {
        EVP_PKEY_free(k);
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    EVP_PKEY_free(k);
    return raw;
}

}
