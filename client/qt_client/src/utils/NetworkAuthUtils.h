#pragma once
#include <string>
#include <map>
#include <nlohmann/json.hpp>
#include "crypto/KeyBundle.h"
#include "crypto/Signer_Ed.h"
#include "crypto/Signer_Dilithium.h"
#include "crypto/FileClientData.h"
#include <QDateTime>

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
    inline std::string makeCanonicalString(const std::string& username, const std::string& timestamp, const std::string& method, const std::string& path, const std::string& bodyJson) {
        std::ostringstream oss;
        oss << username << "|" << timestamp << "|" << method << "|" << path << "|" << bodyJson;
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
    makeAuthHeaders(const std::string& username,
                    const KeyBundle& privBundle,
                    const std::string& method,
                    const std::string& path,
                    const std::string& bodyJson)
    {
        // 1) timestamp in ISO8601 UTC (Qt::ISODate gives e.g. "2025-06-03T15:42:00Z")
        QString qsNow = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        std::string timestamp = qsNow.toStdString();

        // 2) canonical string
        std::string canonical = makeCanonicalString(username, timestamp, method, path, bodyJson);

        // 3) Sign with Ed25519
        auto edPrivB64 = privBundle.getEd25519PrivateKeyBase64();
        auto edPrivRaw = FileClientData::base64_decode(edPrivB64);
        Signer_Ed edSigner;
        edSigner.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
        std::vector<uint8_t> edSig = edSigner.sign(
            std::vector<uint8_t>(canonical.begin(), canonical.end())
            );
        std::string edSigB64 = FileClientData::base64_encode(edSig.data(), edSig.size());

        // 4) Sign with Dilithium
        auto pqPrivB64 = privBundle.getDilithiumPrivateKeyBase64();
        auto pqPrivRaw = FileClientData::base64_decode(pqPrivB64);
        Signer_Dilithium pqSigner;
        pqSigner.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
        std::vector<uint8_t> pqSig = pqSigner.sign(
            std::vector<uint8_t>(canonical.begin(), canonical.end())
            );
        std::string pqSigB64 = FileClientData::base64_encode(pqSig.data(), pqSig.size());

        // 5) Combine
        std::string combined = edSigB64 + "||" + pqSigB64;

        // 6) Build headers
        return {
            { "X-Username",  username },
            { "X-Timestamp", timestamp },
            { "X-Signature", combined }
        };
    }
}
