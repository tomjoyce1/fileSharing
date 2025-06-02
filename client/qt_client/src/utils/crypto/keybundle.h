#pragma once

#include <vector>
#include <string>
#include <sodium.h>
#include <nlohmann/json.hpp>

class KeyBundle {
public:
    /**
     * Default constructor
     *  - Calls sodium_init() (once) to ensure libsodium is ready
     *  - Generates a fresh X25519 keypair, Ed25519 keypair, and Dilithium keypair
     *  - Stores both public AND private keys in this object
     */
    KeyBundle();

    /**
     * Construct from existing public+private keys (all base64‐encoded JSON)
     */
    KeyBundle(
        const std::vector<uint8_t>& x25519Public,
        const std::vector<uint8_t>& ed25519Public,
        const std::vector<uint8_t>& dilithiumPublic,
        const std::vector<uint8_t>& x25519Private,
        const std::vector<uint8_t>& ed25519Private,
        const std::vector<uint8_t>& dilithiumPrivate
        );

    KeyBundle(const KeyBundle& other);
    KeyBundle& operator=(const KeyBundle& other);
    KeyBundle(KeyBundle&& other) noexcept;
    KeyBundle& operator=(KeyBundle&& other) noexcept;
    ~KeyBundle() = default;

    /** Public‐only JSON (what you send to the server) **/
    std::string toJson() const;
    nlohmann::json toJsonPublic()  const;

    /**
     *  Private JSON (public AND private) so you can safely write to disk.
     *  The corresponding fromJsonPrivate(...) will recover both public and private keys.
     */
    nlohmann::json toJsonPrivate() const;
    static KeyBundle fromJson(const std::string& jsonStr);               // parses public‐only JSON
    static KeyBundle fromJsonPrivate(const nlohmann::json& j);           // parses public+private JSON

    // ── Accessors for _public_ keys ─────────────────────────────────────────
    const std::vector<uint8_t>& getX25519Pub()    const { return x25519Pub_; }
    const std::vector<uint8_t>& getEd25519Pub()   const { return ed25519Pub_; }
    const std::vector<uint8_t>& getDilithiumPub() const { return dilithiumPub_; }

    // ── Accessors for _private_ keys (base64‐encoded) ────────────────────────
    // We return them *already* base64‐encoded because that is the easiest for FileUploadHandler.
    // If you need raw bytes instead, call KeyBundle::fromBase64( getEd25519PrivB64() ).
    std::string getX25519PrivateKeyBase64()   const { return toBase64(x25519Priv_);   }
    std::string getEd25519PrivateKeyBase64()  const { return toBase64(ed25519Priv_);  }
    std::string getDilithiumPrivateKeyBase64()const { return toBase64(dilithiumPriv_);}

private:
    // ── Public keys (all binary) ─────────────────────────────────────────────
    std::vector<uint8_t> x25519Pub_;     // 32 bytes
    std::vector<uint8_t> ed25519Pub_;    // crypto_sign_PUBLICKEYBYTES (32) + 32 (seed?), depending on format
    std::vector<uint8_t> dilithiumPub_;  // OQS_SIG_dilithium_5_length

    // ── Private keys (all binary) ────────────────────────────────────────────
    std::vector<uint8_t> x25519Priv_;    // 32 bytes
    std::vector<uint8_t> ed25519Priv_;   // crypto_sign_SECRETKEYBYTES (64)
    std::vector<uint8_t> dilithiumPriv_; // OQS_SIG_dilithium_5_length

    //───────────────────────────────────────────────────────────────────────────
    // Static helpers for Base64 <--> raw binary
    static std::string toBase64(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> fromBase64(
        const std::string& b64,
        const std::string& nameForError
        );
};
