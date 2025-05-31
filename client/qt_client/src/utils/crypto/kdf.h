#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <sodium.h>

/**
 * This is a wrapper around libsodium’s crypto_kdf (HKDF-SHA256) APIs.
 * A Key Derivation Function (KDF) takes an intial master key
 * and stretches it into many independent subkeys.
 *
 * Allows us to combine the two local pre-q and post-q keys to form the FEK
 * The FEK is then fed into the same KDF with a context string to generate the MEK
 */
namespace Kdf {
    inline constexpr size_t MASTER_KEY_BYTES = crypto_kdf_KEYBYTES;
    inline constexpr size_t CONTEXT_BYTES    = crypto_kdf_CONTEXTBYTES;
    inline constexpr size_t BYTES_MAX        = crypto_kdf_BYTES_MAX;


    void generateMasterKey(std::vector<uint8_t>& outMasterKey);

    /**
     * Derives a subkey of length bytes from masterKey, using subkeyId and context.
     *
     * @param masterKey: A 32-byte master key
     * @param subkeyId:A 64-bit integer
     * @param context: 8 ASCII characters
     * @param length: How many bytes you want to derive
     * @param outSubkey: output
     */
    void deriveSubkey(
        const std::vector<uint8_t>& masterKey, uint64_t subkeyId, const std::string& context, size_t length, std::vector<uint8_t>& outSubkey);

    /**
    * Accepts `const char[8]` for context (C-style array).
    * Demonstrates function overloading.
    */
    inline void deriveSubkey(const std::vector<uint8_t>& masterKey, uint64_t subkeyId, const char contextCstr[CONTEXT_BYTES], size_t length, std::vector<uint8_t>& outSubkey) {
        // Calls the main overload by converting char[8] to std::string
        deriveSubkey(masterKey, subkeyId, std::string(contextCstr, CONTEXT_BYTES), length, outSubkey);
    }

}
