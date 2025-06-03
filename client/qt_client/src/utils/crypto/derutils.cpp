#include "DerUtils.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
#include <openssl/x509.h>

namespace der {
    std::vector<uint8_t> toSpkiDer(int nid, const uint8_t* raw, std::size_t rawLen) {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(nid, nullptr, raw, rawLen);
        if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_public_key failed");

        int derLen = i2d_PUBKEY(pkey, nullptr);
        std::vector<uint8_t> der(derLen);

        unsigned char* out = der.data();
        i2d_PUBKEY(pkey, &out);

        EVP_PKEY_free(pkey);
        return der;
    }
}
