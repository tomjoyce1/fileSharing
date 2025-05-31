#include "Symmetric.h"
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>


EVP_CIPHER_CTX* Symmetric::create_ctx() {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Symmetric::create_ctx: EVP_CIPHER_CTX_new failed");
    }
    return ctx;
}


Symmetric::Ciphertext Symmetric::encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& key) {
    // Validate key length
    if (key.size() != 32) {
        throw std::invalid_argument("Symmetric::encrypt: key must be 32 bytes for AES-256");
    }

    // Generate random 16-byte IV
    std::vector<uint8_t> iv(16);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Symmetric::encrypt: RAND_bytes failed");
    }

    // Create and manage an EVP_CIPHER_CTX*
    EVP_CIPHER_CTX* raw_ctx = create_ctx();
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    // Initialize for AES-256-CTR encryption
    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr,
                                key.data(), iv.data())) {
        throw std::runtime_error("Symmetric::encrypt: EVP_EncryptInit_ex failed");
    }

    // Allocate a buffer
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_ctr());
    std::vector<uint8_t> ciphertext(plaintext.size() + block_size);

    int out_len1 = 0;
    if (1 != EVP_EncryptUpdate(ctx.get(),
                               ciphertext.data(), &out_len1,
                               plaintext.data(), plaintext.size())) {
        throw std::runtime_error("Symmetric::encrypt: EVP_EncryptUpdate failed");
    }

    int out_len2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx.get(),
                                 ciphertext.data() + out_len1, &out_len2)) {
        throw std::runtime_error("Symmetric::encrypt: EVP_EncryptFinal_ex failed");
    }

    // Resize to actual ciphertext length
    ciphertext.resize(out_len1 + out_len2);

    return Ciphertext{ std::move(ciphertext), std::move(iv) };
}


Symmetric::Plaintext Symmetric::decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv) {
    if (key.size() != 32) {
        throw std::invalid_argument("Symmetric::decrypt: key must be 32 bytes for AES-256");
    }

    if (iv.size() != 16) {
        throw std::invalid_argument("Symmetric::decrypt: iv must be 16 bytes for AES-256-CTR");
    }


    EVP_CIPHER_CTX* raw_ctx = create_ctx();
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr,
                                key.data(), iv.data())) {
        throw std::runtime_error("Symmetric::decrypt: EVP_DecryptInit_ex failed");
    }

    int block_size = EVP_CIPHER_block_size(EVP_aes_256_ctr());
    std::vector<uint8_t> plaintext(ciphertext.size() + block_size);

    int out_len1 = 0;
    if (1 != EVP_DecryptUpdate(ctx.get(),
                               plaintext.data(), &out_len1,
                               ciphertext.data(), ciphertext.size())) {
        throw std::runtime_error("Symmetric::decrypt: EVP_DecryptUpdate failed");
    }

    int out_len2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx.get(),
                                 plaintext.data() + out_len1, &out_len2)) {
        // Note: If the ciphertext is tampered or wrong key/IV, Final_ex may fail.
        throw std::runtime_error("Symmetric::decrypt: EVP_DecryptFinal_ex failed");
    }

    plaintext.resize(out_len1 + out_len2);

    return Plaintext{ std::move(plaintext) };
}
