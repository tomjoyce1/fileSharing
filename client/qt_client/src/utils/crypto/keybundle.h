// KeyBundle.h

#pragma once

#include <vector>
#include <string>
#include <nlohmann/json.hpp>

/**
 * KeyBundle
 *
 * In memory, this class stores **raw** public keys:
 *   • X25519 (32 bytes)
 *   • Ed25519 (32 bytes)
 *   • Dilithium-5 (≈2592 bytes)
 *
 * and their corresponding **raw** private keys:
 *   • X25519 (32 bytes)
 *   • Ed25519 (64 bytes)
 *   • Dilithium-5 (≈4896 bytes)
 *
 * Only when converting to JSON does it wrap the raw public keys
 * into SPKI-DER (44 bytes for X25519/Ed25519) exactly once, then
 * Base64–encode.  Likewise, `fromJsonPublic()` does Base64 → DER → raw.
 *
 * toJsonPublic()/fromJsonPublic() deal only with the three public keys.
 * toJsonPrivate()/fromJsonPrivate() include all six raw buffers (Base64-encoded).
 */
class KeyBundle {
public:
    //── Constructors / Assignment / Destructors ─────────────────────────────────

    /** Default ctor: generate a fresh X25519, Ed25519, Dilithium-5 keypair (raw). */
    KeyBundle();

    /** “Public-only” ctor: supply three raw public keys (32, 32, ~2592 bytes). */
    KeyBundle(
        const std::vector<uint8_t>& x25519PublicRaw,
        const std::vector<uint8_t>& ed25519PublicRaw,
        const std::vector<uint8_t>& dilithiumPublicRaw
        );

    /**
     * “Full” ctor: supply all six raw buffers:
     *   • X25519 public (32 bytes)
     *   • Ed25519 public (32 bytes)
     *   • Dilithium-5 public (~2592 bytes)
     *   • X25519 private (32 bytes)
     *   • Ed25519 private (64 bytes)
     *   • Dilithium-5 private (~4896 bytes)
     */
    KeyBundle(
        const std::vector<uint8_t>& x25519PublicRaw,
        const std::vector<uint8_t>& ed25519PublicRaw,
        const std::vector<uint8_t>& dilithiumPublicRaw,
        const std::vector<uint8_t>& x25519PrivateRaw,
        const std::vector<uint8_t>& ed25519PrivateRaw,
        const std::vector<uint8_t>& dilithiumPrivateRaw
        );

    KeyBundle(const KeyBundle& other);
    KeyBundle& operator=(const KeyBundle& other);
    KeyBundle(KeyBundle&& other) noexcept;
    KeyBundle& operator=(KeyBundle&& other) noexcept;
    ~KeyBundle() = default;

    //── JSON Serialization / Deserialization ────────────────────────────────────

    /**
     * toJsonPublic(): emit a JSON object (nlohmann::json) containing only the
     * public keys.  Internally does:
     *   raw → SPKI-DER (44 bytes) → Base64 → JSON.
     *
     * Output shape:
     * {
     *   "preQuantum": {
     *     "identityKemPublicKey":     "<44-byte DER, Base64>",
     *     "identitySigningPublicKey": "<44-byte DER, Base64>"
     *   },
     *   "postQuantum": {
     *     "identitySigningPublicKey": "<raw Dilithium-5, Base64>"
     *   }
     * }
     */
    nlohmann::json toJsonPublic() const;

    /**
     * fromJsonPublic(): parse exactly what toJsonPublic() emits.
     *   JSON → Base64 → DER (44 bytes) → raw (32 bytes) for X25519/Ed25519.
     *   JSON → Base64 → raw PQ (~2592 bytes) for Dilithium-5.
     */
    static KeyBundle fromJsonPublic(const std::string& jsonStr);

    /**
     * toJsonPrivate(): emit a JSON object containing all six keys.  Public keys
     * are DER-wrapped + Base64; private keys are raw + Base64.  Used for client-side
     * storage (encrypted under password).
     */
    nlohmann::json toJsonPrivate() const;

    /**
     * fromJsonPrivate(): parse exactly what toJsonPrivate() emits,
     * reconstructing all six raw buffers.
     */
    static KeyBundle fromJsonPrivate(const nlohmann::json& j);

    //── Accessors for Raw Public Keys ──────────────────────────────────────────

    const std::vector<uint8_t>& getX25519PublicRaw()    const { return x25519PubRaw_; }
    const std::vector<uint8_t>& getEd25519PublicRaw()   const { return ed25519PubRaw_; }
    const std::vector<uint8_t>& getDilithiumPublicRaw() const { return dilithiumPubRaw_; }

    //── Accessors for Base64-encoded Private Keys ─────────────────────────────

    /** Returns Base64(raw X25519 private, 32 bytes). */
    std::string getX25519PrivateKeyBase64()    const;

    /** Returns Base64(raw Ed25519 private, 64 bytes). */
    std::string getEd25519PrivateKeyBase64()   const;

    /** Returns Base64(raw Dilithium-5 private, ~4896 bytes). */
    std::string getDilithiumPrivateKeyBase64() const;

private:
    //── In-Memory Fields (all raw) ─────────────────────────────────────────────

    // PUBLIC (raw):
    std::vector<uint8_t> x25519PubRaw_;     // 32 bytes raw
    std::vector<uint8_t> ed25519PubRaw_;    // 32 bytes raw
    std::vector<uint8_t> dilithiumPubRaw_;  // ~2592 bytes raw

    // PRIVATE (raw):
    std::vector<uint8_t> x25519PrivRaw_;    // 32 bytes raw
    std::vector<uint8_t> ed25519PrivRaw_;   // 64 bytes raw
    std::vector<uint8_t> dilithiumPrivRaw_; // ~4896 bytes raw

    //── Internal Base64 Helpers ─────────────────────────────────────────────────

    /** Base64-encode a raw byte buffer. */
    static std::string toBase64(const std::vector<uint8_t>& data);

    /** Base64-decode a string into a raw byte buffer (throws on error). */
    static std::vector<uint8_t> fromBase64(
        const std::string& b64,
        const std::string& nameForError
        );
};
