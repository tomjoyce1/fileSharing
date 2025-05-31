#include "Hash.h"
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>

namespace Hash {
    // Helper: throw a runtime_error if any OpenSSL EVP call fails.
    static void throwIfZero(int ok, const char* msg) {
        if (ok != 1) {
            throw std::runtime_error(msg);
        }
    }

    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        return sha256(data.data(), data.size());
    }

    std::vector<uint8_t> sha256(const uint8_t* dataPtr, size_t len) {
        // Create an EVP_MD_CTX
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Hash::sha256: EVP_MD_CTX_new failed");
        }

        // Initialize for SHA-256
        throwIfZero(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr),
                    "Hash::sha256: EVP_DigestInit_ex failed");

        // Feed the data
        throwIfZero(EVP_DigestUpdate(ctx, dataPtr, len),
                    "Hash::sha256: EVP_DigestUpdate failed");

        // Finalize
        std::vector<uint8_t> digest(EVP_MD_size(EVP_sha256()));
        unsigned int outLen = 0;
        throwIfZero(EVP_DigestFinal_ex(ctx, digest.data(), &outLen),
                    "Hash::sha256: EVP_DigestFinal_ex failed");

        // outLen should be 32 for SHA-256
        if (outLen != EVP_MD_size(EVP_sha256())) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Hash::sha256: Unexpected digest length");
        }

        EVP_MD_CTX_free(ctx);
        return digest;
    }
}
