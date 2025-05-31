#pragma once
#include <vector>
#include <string>
#include <sodium.h>


class KeyBundle {
public:
    /**
     * Default constructor
     *  - Calls sodium_init() (once) to ensure libsodium is ready
     *  - Generates a fresh X25519 keypair, Ed25519 keypair, and Dilithium keypair
     *  - Stores only the public keys in this object
     */
    KeyBundle();

    /**
     * Parameterized constructor
     *  Initialize from existing public keys
     */
    KeyBundle(
        const std::vector<uint8_t>& x25519Public,
        const std::vector<uint8_t>& ed25519Public,
        const std::vector<uint8_t>& dilithiumPublic
        );

    /**
     * Copy constructor
     */
    KeyBundle(const KeyBundle& other);

    /**
     * Copy assignment operator
     */
    KeyBundle& operator=(const KeyBundle& other);

    /**
     * Move constructor
     */
    KeyBundle(KeyBundle&& other) noexcept;

    /**
     * Move assignment operator
     */
    KeyBundle& operator=(KeyBundle&& other) noexcept;

    /**
     * Destructor
     */
    ~KeyBundle() = default;

    /**
     *  Returns a JSON‐formatted string containing Base64‐encoded public keys.
     */
    std::string toJson() const;

    /**
     * fromJson
     *  Returns a KeyBundle whose public‐key vectors are set accordingly.
     */
    static KeyBundle fromJson(const std::string& jsonStr);

    // Accessors
    const std::vector<uint8_t>& getX25519Pub()    const { return x25519Pub_; }
    const std::vector<uint8_t>& getEd25519Pub()   const { return ed25519Pub_; }
    const std::vector<uint8_t>& getDilithiumPub() const { return dilithiumPub_; }

private:
    // The three public-key bytevectors:
    std::vector<uint8_t> x25519Pub_;     // 32 bytes (X25519)
    std::vector<uint8_t> ed25519Pub_;    // crypto_sign_PUBLICKEYBYTES (Ed25519)
    std::vector<uint8_t> dilithiumPub_;  // OQS_SIG_dilithium_2_length (Dilithium2)

    // Static helpers for Base64 encoding/decoding (using libsodium):
    static std::string toBase64(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> fromBase64(
        const std::string& b64,
        const std::string& nameForError
        );
};
