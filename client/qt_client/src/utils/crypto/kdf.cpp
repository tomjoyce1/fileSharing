#include "Kdf.h"

void Kdf::generateMasterKey(std::vector<uint8_t>& outMasterKey) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Kdf::generateMasterKey: sodium_init failed");
    }

    outMasterKey.resize(MASTER_KEY_BYTES);
    // Fill with random bytes
    randombytes_buf(outMasterKey.data(), static_cast<size_t>(outMasterKey.size()));
}

void Kdf::deriveSubkey(const std::vector<uint8_t>& masterKey, uint64_t subkeyId, const std::string& context, size_t length, std::vector<uint8_t>& outSubkey) {
    // Validate input lengths
    if (masterKey.size() != MASTER_KEY_BYTES) {
        throw std::invalid_argument("Kdf::deriveSubkey: masterKey must be exactly 32 bytes");
    }
    if (context.size() != CONTEXT_BYTES) {
        throw std::invalid_argument("Kdf::deriveSubkey: context must be exactly 8 characters");
    }
    if (length == 0 || length > BYTES_MAX) {
        throw std::invalid_argument("Kdf::deriveSubkey: length must be between 1 and crypto_kdf_BYTES_MAX");
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("Kdf::deriveSubkey: sodium_init failed");
    }

    outSubkey.resize(length);
    // Call derivation function
    if (crypto_kdf_derive_from_key(outSubkey.data(), static_cast<size_t>(length), subkeyId, context.c_str(), masterKey.data()) != 0) {
        throw std::runtime_error("Kdf::deriveSubkey: crypto_kdf_derive_from_key failed");
    }
}
