#pragma once

#include "CryptoBase.h"
#include <array>
#include <cstdint>
#include <string>
#include <sodium.h>           // for randombytes_buf, sodium_bin2base64, sodium_base642bin
#include <vector>
#include <sstream>            // for std::ostringstream (used in buildDebugString)
#include <stdexcept>
#include <nlohmann/json.hpp>  // https://github.com/nlohmann/json

/**
 * FileClientData holds the 4 secret values needed to decrypt or re‐share a file,
 * plus the file_id and filename.  Inherits from CryptoBase so we can use:
 *   - KEY_LEN (32)
 *   - NONCE_LEN (16)
 *   - zeroizeBuffer()
 *
 * Also includes inline base64 helpers so you do not need a separate utils file.
 *
 * Chris C++ Requirements:
 * - Access Specifiers
 * - this Pointer
 */
struct FileClientData : public CryptoBase {
    static constexpr std::size_t PUBLIC_NONCE_LEN = NONCE_LEN;
    static constexpr std::size_t PUBLIC_KEY_LEN   = KEY_LEN;

    // AES‐256: 32‐byte FEK for file content
    std::array<uint8_t, KEY_LEN> fek{};

    // 16‐byte IV for file content
    std::array<uint8_t, NONCE_LEN> file_nonce{};

    // AES‐256: 32‐byte MEK for metadata
    std::array<uint8_t, KEY_LEN> mek{};

    // 16‐byte IV for metadata
    std::array<uint8_t, NONCE_LEN> metadata_nonce{};

    // The integer file_id assigned by the server, or 0 if not yet assigned
    uint64_t file_id{0};

    // Original filename on disk
    std::string filename;

    //───────────────────────────────────────────────────────────────────────────
    // 1) Default constructor (zero‐initializes everything)
    FileClientData() = default;

    // 2) “Randomize” constructor
    //
    //    If you call FileClientData(true), it will fill FEK/MEK and nonces with randomness.
    //    If you call FileClientData(false), it will leave them zeroed.
    explicit FileClientData(bool generate)
    {
        if (generate) {
            // Generate FEK (32 bytes) and MEK (32 bytes):
            randombytes_buf(fek.data(), KEY_LEN);
            randombytes_buf(mek.data(), KEY_LEN);

            // Generate nonces (16 bytes each)
            randombytes_buf(file_nonce.data(), NONCE_LEN);
            randombytes_buf(metadata_nonce.data(), NONCE_LEN);
        }
    }

    /**
     * Explicitly zero out all secret buffers when no longer needed.
     * Demonstrates calling CryptoBase::zeroizeBuffer().
     */
    void wipeSensitive() {
        zeroizeBuffer(fek.data(), KEY_LEN);
        zeroizeBuffer(mek.data(), KEY_LEN);
        zeroizeBuffer(file_nonce.data(), NONCE_LEN);
        zeroizeBuffer(metadata_nonce.data(), NONCE_LEN);
    }

    /**
     * Build a simple debug string (shows file_id, filename, first bytes of FEK/MEK).
     * Uses std::ostringstream, so we include <sstream> above.
     * Demonstrates use of 'this->' to refer to members.
     */
    std::string buildDebugString() const {
        std::ostringstream oss;
        oss << "FileClientData("
            << "file_id=" << this->file_id
            << ", filename=\"" << this->filename << "\""
            << ", fek[0]=0x" << std::hex << std::setw(2)
            << static_cast<int>(this->fek[0])
            << ", mek[0]=0x" << std::hex << std::setw(2)
            << static_cast<int>(this->mek[0])
            << ")";
        return oss.str();
    }

    //───────────────────────────────────────────────────────────────────────────
    // 3) Base64 Encode / Decode Helpers (using libsodium)
    //
    //    These functions let you convert binary buffers to/from Base64 strings,
    //    so that you can embed them in JSON.  They are placed here so you do not need
    //    a separate “utils” file.
    //
    //    You must call sodium_init() somewhere in main() before ever using these.
    //
    static std::string base64_encode(const uint8_t* data, size_t len) {
        // Calculate needed length for the Base64 buffer:
        // sodium_base642bin() output length = 4 * ceil(n/3).  We can allocate a bit more.
        size_t needed = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
        std::string out;
        out.resize(needed);
        sodium_bin2base64(
            out.data(),
            needed,
            data,
            len,
            sodium_base64_VARIANT_ORIGINAL
            );
        // sodium_bin2base64 writes a NUL terminator, so strip it off:
        if (!out.empty() && out.back() == '\0') {
            out.pop_back();
        }
        return out;
    }

    static std::vector<uint8_t> base64_decode(const std::string& b64) {
        // Estimate maximum decoded length = 3 * (b64.size()/4)
        size_t maxDecodedLen = (b64.size() / 4) * 3 + 1;
        std::vector<uint8_t> out(maxDecodedLen);

        size_t actualLen = 0;
        if (sodium_base642bin(
                out.data(),
                maxDecodedLen,
                b64.data(),
                b64.size(),
                nullptr,            // ignore whitespace chars automatically
                &actualLen,
                nullptr,            // no “chars left over” pointer
                sodium_base64_VARIANT_ORIGINAL) != 0)
        {
            throw std::runtime_error("base64_decode: invalid input");
        }
        out.resize(actualLen);
        return out;
    }

    //───────────────────────────────────────────────────────────────────────────
    // 4) JSON Serialization / Deserialization
    //
    //    Uses nlohmann::json to convert to/from JSON.  Relies on the base64 helpers above.
    //
    nlohmann::json to_json() const {
        nlohmann::json j;
        j["file_id"]            = file_id;
        j["filename"]           = filename;
        j["fek_b64"]            = base64_encode(fek.data(), KEY_LEN);
        j["file_nonce_b64"]     = base64_encode(file_nonce.data(), NONCE_LEN);
        j["mek_b64"]            = base64_encode(mek.data(), KEY_LEN);
        j["metadata_nonce_b64"] = base64_encode(metadata_nonce.data(), NONCE_LEN);
        return j;
    }

    static FileClientData from_json(const nlohmann::json& j) {
        FileClientData fcd;
        fcd.file_id  = j.at("file_id").get<uint64_t>();
        fcd.filename = j.at("filename").get<std::string>();

        auto decodeField = [&](const std::string& fieldName, uint8_t* outBuf, size_t expectedLen) {
            std::string b64str = j.at(fieldName).get<std::string>();
            std::vector<uint8_t> tmp = base64_decode(b64str);
            if (tmp.size() != expectedLen) {
                throw std::runtime_error("from_json: length mismatch for " + fieldName);
            }
            std::memcpy(outBuf, tmp.data(), expectedLen);
        };

        decodeField("fek_b64",            fcd.fek.data(),            KEY_LEN);
        decodeField("file_nonce_b64",     fcd.file_nonce.data(),     NONCE_LEN);
        decodeField("mek_b64",            fcd.mek.data(),            KEY_LEN);
        decodeField("metadata_nonce_b64", fcd.metadata_nonce.data(), NONCE_LEN);

        return fcd;
    }
};
