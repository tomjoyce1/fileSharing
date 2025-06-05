// ─── DerUtils.h ───────────────────────────────────────────────────────────────
#pragma once
#include <vector>
#include <cstddef>
#include <openssl/evp.h>

namespace der {

/// Return true if the buffer already looks like a 44-byte SPKI for the NID.
bool isSpki(const uint8_t* buf, std::size_t len, int openssl_nid);

/// If `rawLen==32`  → wrap once and return the 44-byte SPKI
/// If `rawLen==44`  → assume it *is* SPKI already and just return a copy
std::vector<uint8_t> toSpkiOrPassthrough(int nid,
                                         const uint8_t* raw,
                                         std::size_t    rawLen);

/// Convenience wrappers
inline std::vector<uint8_t> x25519(const std::vector<uint8_t>& v) {
    return toSpkiOrPassthrough(EVP_PKEY_X25519, v.data(), v.size());
}
inline std::vector<uint8_t> ed25519(const std::vector<uint8_t>& v) {
    return toSpkiOrPassthrough(EVP_PKEY_ED25519, v.data(), v.size());
}

/// DER(44) → RAW(32).  Throws if the buffer is not a valid SPKI.
std::vector<uint8_t> parseX25519Spki(const std::vector<uint8_t>& der);
std::vector<uint8_t> parseEd25519Spki(const std::vector<uint8_t>& der);

} // namespace der
