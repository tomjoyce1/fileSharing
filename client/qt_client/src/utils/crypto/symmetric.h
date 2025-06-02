#pragma once
#include <vector>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * Wrapper around AES-256-CTR encryption/decryption, using OpenSSL's EVP API.
 *
 * CPP:
 */
class Symmetric {
public:
    struct Ciphertext {
        std::vector<uint8_t> data;  // ciphertext bytes
        std::vector<uint8_t> iv;
    };

    struct Plaintext {
        std::vector<uint8_t> data;  // plaintext bytes
    };

    /**
     * Encrypts plaintext using AES-256-CTR with with the key
     */
    static Ciphertext encrypt(const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& key);

    /**
     * Decrypts the ciphertext using AES-256-CTR with the key and the IV.
     */
    static Plaintext decrypt(const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& iv);

private:
    // Helper
    static EVP_CIPHER_CTX* create_ctx();

    // Prevent instantiation of this class because all methods are static
    Symmetric() = delete;
    ~Symmetric() = delete;

    // Disable copy/move
    Symmetric(const Symmetric&) = delete;
    Symmetric& operator=(const Symmetric&) = delete;
    Symmetric(Symmetric&&) = delete;
    Symmetric& operator=(Symmetric&&) = delete;
};
