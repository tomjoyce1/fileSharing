#include "SigningHelper.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <sodium.h>
#include <oqs/oqs.h>

namespace {
/**
     * Decode a Base64‐encoded string into raw bytes using libsodium.
     * - input: Base64 string (standard variant, padded)
     * - output: vector<uint8_t> containing raw bytes
     *
     * Throws std::runtime_error if decode fails.
     */
std::vector<uint8_t> decodeBase64(const std::string& b64) {
    if (b64.empty()) {
        return {};
    }
    std::vector<uint8_t> bin(b64.size()); // allocate enough space
    size_t binLen = 0;
    int ret = sodium_base642bin(
        bin.data(),
        bin.size(),
        b64.c_str(),
        b64.size(),
        nullptr,      // no ignore chars
        &binLen,
        nullptr,      // no invalid position
        sodium_base64_VARIANT_ORIGINAL
        );
    if (ret != 0) {
        throw std::runtime_error("Base64 decode failed");
    }
    bin.resize(binLen);
    return bin;
}

/**
     * Encode raw bytes into a Base64‐encoded string using libsodium.
     * - data: pointer to raw bytes
     * - dataLen: length of raw bytes
     * Returns: Base64‐encoded string (standard variant, padded).
     */
std::string encodeBase64(const uint8_t* data, size_t dataLen) {
    size_t encodedLen = sodium_base64_encoded_len(dataLen, sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> b64buf(encodedLen);
    sodium_bin2base64(
        b64buf.data(),
        encodedLen,
        data,
        dataLen,
        sodium_base64_VARIANT_ORIGINAL
        );
    return std::string(b64buf.data());
}
}

std::string SigningHelper::currentTimestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto nowSecs = time_point_cast<seconds>(now);
    std::time_t t = system_clock::to_time_t(nowSecs);

    std::tm tm_utc;
#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string SigningHelper::createHybridSignature(
    const std::string& username,
    const std::string& timestamp,
    const std::string& method,
    const std::string& path,
    const std::string& body,
    const std::string& ed25519Sk,
    const std::string& dilithiumSk
    ) {
    // 1) Build the canonical string: "username|timestamp|method|path|body"
    std::ostringstream canon;
    canon << username << "|"
          << timestamp << "|"
          << method << "|"
          << path << "|"
          << body;
    std::string canonicalString = canon.str();
    const uint8_t* msg = reinterpret_cast<const uint8_t*>(canonicalString.data());
    size_t msgLen = canonicalString.size();

    // 2) Initialize libsodium if needed
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }

    // 3) Decode Ed25519 secret key from Base64
    std::vector<uint8_t> edSkRaw = decodeBase64(ed25519Sk);
    if (edSkRaw.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error("Invalid Ed25519 secret key length");
    }

    // 4) Sign with Ed25519 (detached)
    std::vector<uint8_t> edSig(crypto_sign_BYTES);
    unsigned long long edSigLen = 0;
    if (crypto_sign_detached(
            edSig.data(), &edSigLen,
            msg, msgLen,
            edSkRaw.data()) != 0) {
        throw std::runtime_error("Ed25519 signature generation failed");
    }

    // 5) Decode Dilithium2 secret key from Base64
    std::vector<uint8_t> dilSkRaw = decodeBase64(dilithiumSk);

    // 6) Create OQS context for Dilithium2
    OQS_SIG* oqsS = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (oqsS == nullptr) {
        throw std::runtime_error("OQS_SIG_new(Dilithium2) failed");
    }
    if (dilSkRaw.size() != static_cast<size_t>(oqsS->length_secret_key)) {
        OQS_SIG_free(oqsS);
        throw std::runtime_error("Invalid Dilithium2 secret key length");
    }

    // 7) Sign with Dilithium2
    std::vector<uint8_t> dilSig(oqsS->length_signature);
    size_t dilSigLen = 0;
    if (OQS_SIG_sign(
            oqsS,
            dilSig.data(), &dilSigLen,
            msg, msgLen,
            dilSkRaw.data()) != OQS_SUCCESS) {
        OQS_SIG_free(oqsS);
        throw std::runtime_error("Dilithium2 signature generation failed");
    }
    dilSig.resize(dilSigLen);

    // 8) Free the OQS context
    OQS_SIG_free(oqsS);

    // 9) Base64‐encode both signatures
    std::string edSigB64  = encodeBase64(edSig.data(), static_cast<size_t>(edSigLen));
    std::string dilSigB64 = encodeBase64(dilSig.data(), dilSigLen);

    // 10) Concatenate with "||"
    return edSigB64 + "||" + dilSigB64;
}
