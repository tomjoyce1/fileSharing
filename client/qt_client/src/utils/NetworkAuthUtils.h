#pragma once
#include <string>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>
#include <QDateTime>
#include "crypto/KeyBundle.h"
#include "crypto/Signer_Ed.h"
#include "crypto/Signer_Dilithium.h"
#include "crypto/FileClientData.h"

/**
 * NetworkAuthUtils
 *
 * Builds the standard dual‐signature authentication headers:
 *   X-Username, X-Timestamp, X-Signature
 *
 * Usage:
 *   auto headers = NetworkAuthUtils::makeAuthHeaders(
 *                    myUsername,
 *                    myKeyBundlePrivate,
 *                    "POST",
 *                    "/api/fs/upload",
 *                    jsonBody.dump()
 *                 );
 */
namespace NetworkAuthUtils
{
/**
     * Create a canonical request string = username|timestamp|method|path|bodyJson.
     */
inline std::string makeCanonicalString(
    const std::string& username,
    const std::string& timestamp,
    const std::string& method,
    const std::string& path,
    const std::string& bodyJson
    ) {
    std::ostringstream oss;
    oss << username
        << "|" << timestamp
        << "|" << method
        << "|" << path
        << "|" << bodyJson;
    return oss.str();
}

/**
     * Given:
     *   - username (string)
     *   - the private portion of KeyBundle (contains Ed25519 + Dilithium keys)
     *   - HTTP method (e.g. "POST")
     *   - path (e.g. "/api/fs/upload")
     *   - bodyJson (already‐serialized JSON string)
     *
     * Returns a map of:
     *   {
     *     "X-Username"  : username,
     *     "X-Timestamp" : ISO8601‐UTC timestamp,
     *     "X-Signature" : base64(ed25519(canonical)) || base64(dilithium(canonical))
     *   }
     */
inline std::map<std::string, std::string>
makeAuthHeaders(
    const std::string& username,
    const KeyBundle&   privBundle,
    const std::string& method,
    const std::string& path,
    const std::string& bodyJson
    )
{
    // 1) timestamp in ISO8601 UTC (Qt::ISODate gives e.g. "2025-06-03T15:42:00Z")
    QString qsNow = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    std::string timestamp = qsNow.toStdString();

    // 2) canonical string
    std::string canonical = makeCanonicalString(username, timestamp, method, path, bodyJson);

    //
    // ─── Ed25519 sign that canonical ───
    //
    // 3a) Decode base64→raw bytes
    std::string edPrivB64 = privBundle.getEd25519PrivateKeyBase64();
    std::vector<uint8_t> edPrivRaw = FileClientData::base64_decode(edPrivB64);

    // 3b) Sanity‐check: libsodium’s secret key is 64 bytes (seed||public)
    if (edPrivRaw.size() != static_cast<size_t>(crypto_sign_SECRETKEYBYTES)) {
        throw std::runtime_error(
            "Ed25519 private key length is incorrect (" +
            std::to_string(edPrivRaw.size()) + " bytes; expected " +
            std::to_string(crypto_sign_SECRETKEYBYTES) + ")"
            );
    }

    // 3c) Instantiate Signer_Ed, load the 64‐byte secret, and sign
    Signer_Ed edSigner;
    edSigner.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
    std::vector<uint8_t> edSig = edSigner.sign(
        std::vector<uint8_t>(canonical.begin(), canonical.end())
        );
    std::string edSigB64 = FileClientData::base64_encode(edSig.data(), edSig.size());

    //
    // ─── Dilithium sign that canonical ───
    //
    // 4a) Decode base64→raw bytes
    std::string pqPrivB64 = privBundle.getDilithiumPrivateKeyBase64();
    std::vector<uint8_t> pqPrivRaw = FileClientData::base64_decode(pqPrivB64);

    // 4b) Instantiate Signer_Dilithium, load the secret, and sign
    Signer_Dilithium pqSigner;
    pqSigner.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
    std::vector<uint8_t> pqSig = pqSigner.sign(
        std::vector<uint8_t>(canonical.begin(), canonical.end())
        );
    std::string pqSigB64 = FileClientData::base64_encode(pqSig.data(), pqSig.size());

    // 5) Combine both signatures
    std::string combined = edSigB64 + "||" + pqSigB64;

    // 6) Build headers
    return {
        { "X-Username",  username },
        { "X-Timestamp", timestamp },
        { "X-Signature", combined }
    };
}
}
