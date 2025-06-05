#pragma once

#include <vector>
#include <cstddef>
#include <openssl/evp.h>

/**
 * Helper functions for:
 *   1) Wrapping a 32‐byte raw public key into an SPKI‐DER blob.
 *   2) Parsing an SPKI‐DER blob back into the raw public key bytes.
 *
 * In other words:
 *   toSpkiDer(nid, raw32, 32)   → (44‐byte SPKI DER)
 *   parseSpkiDer(nid, der44, 44) → (32‐byte raw)
 *
 * We expose convenient inline wrappers for X25519 and Ed25519:
 *   der::x25519(rawVec32)   ← wraps 32‐byte → 44‐byte
 *   der::ed25519(rawVec32)  ← wraps 32‐byte → 44‐byte
 *
 *   der::parseX25519Spki(der44)   ← yields 32‐byte raw
 *   der::parseEd25519Spki(der44)  ← yields 32‐byte raw
 *
 * (If you also need Dilithium‐SPKI, you can copy the same pattern,
 * but for brevity this file only shows X25519 & Ed25519.)
 */

namespace der {

//
//  1) Generic wrap/parse routines
//

/**
     * toSpkiDer(nid, raw, rawLen) → a std::vector<uint8_t> containing
     * the SPKI‐DER encoding of that “raw” public key.  Internally,
     * it calls EVP_PKEY_new_raw_public_key(nid, …), then i2d_PUBKEY(…).
     */
std::vector<uint8_t> toSpkiDer(int openssl_nid,
                               const uint8_t* raw,
                               std::size_t rawLen);

/**
     * parseSpkiDer(nid, derPtr, derLen) → a std::vector<uint8_t> containing
     * exactly the “raw” public key bytes.  Internally, it uses d2i_PUBKEY(…)
     * to reconstruct an EVP_PKEY*, then EVP_PKEY_get_raw_public_key(…).
     */
std::vector<uint8_t> parseSpkiDer(int openssl_nid,
                                  const uint8_t* derBytes,
                                  std::size_t derLen);

//
//  2) Inline wrappers for X25519 and Ed25519 (32‐byte raw → 44‐byte DER)
//

inline std::vector<uint8_t> x25519(const std::vector<uint8_t>& raw32) {
    // raw32 must be exactly 32 bytes
    return toSpkiDer(EVP_PKEY_X25519, raw32.data(), raw32.size());
}

inline std::vector<uint8_t> ed25519(const std::vector<uint8_t>& raw32) {
    // raw32 must be exactly 32 bytes
    return toSpkiDer(EVP_PKEY_ED25519, raw32.data(), raw32.size());
}

//
//  3) Inline “parse” wrappers for X25519 and Ed25519 (44‐byte DER → 32 raw)
//

inline std::vector<uint8_t> parseX25519Spki(const std::vector<uint8_t>& der) {
    return parseSpkiDer(EVP_PKEY_X25519, der.data(), der.size());
}

inline std::vector<uint8_t> parseEd25519Spki(const std::vector<uint8_t>& der) {
    return parseSpkiDer(EVP_PKEY_ED25519, der.data(), der.size());
}


} // namespace der
