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
    ) {
    qDebug().nospace()
        << "[NetworkAuthUtils] makeAuthHeaders ENTRY"
           " username=\"" << username << "\""
                       ", method=\"" << method << "\""
                     ", path=\"" << path << "\""
                   ", bodyJson.len=" << bodyJson.size();

    // 1) timestamp in ISO8601 UTC
    QString qsNow = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    std::string timestamp = qsNow.toStdString();
    qDebug().nospace()
        << "[NetworkAuthUtils] timestamp = \"" << timestamp << "\"";

    // 2) canonical string
    std::string canonical = makeCanonicalString(username, timestamp, method, path, bodyJson);


    try {
        //
        // ─── Ed25519 sign that canonical ───────────────────────────────────────
        //
        std::string edPrivB64 = privBundle.getEd25519PrivateKeyBase64();
        qDebug().nospace()
            << "[NetworkAuthUtils] edPrivB64.len=" << edPrivB64.size();
        std::vector<uint8_t> edPrivRaw = FileClientData::base64_decode(edPrivB64);
        qDebug().nospace()
            << "[NetworkAuthUtils] after base64_decode(edPrivB64): edPrivRaw.size="
            << edPrivRaw.size();

        Signer_Ed edSigner;
        edSigner.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
        qDebug() << "[NetworkAuthUtils] Signer_Ed loaded successfully";

        std::vector<uint8_t> edSig = edSigner.sign(
            std::vector<uint8_t>(canonical.begin(), canonical.end())
            );
        qDebug().nospace()
            << "[NetworkAuthUtils] edSig.size=" << edSig.size();

        std::string edSigB64 = FileClientData::base64_encode(edSig.data(), edSig.size());

        //
        // ─── Dilithium sign that canonical ─────────────────────────────────────
        //
        std::string pqPrivB64 = privBundle.getDilithiumPrivateKeyBase64();
        qDebug().nospace()
            << "[NetworkAuthUtils] pqPrivB64.len=" << pqPrivB64.size();
        std::vector<uint8_t> pqPrivRaw = FileClientData::base64_decode(pqPrivB64);
        qDebug().nospace()
            << "[NetworkAuthUtils] after base64_decode(pqPrivB64): pqPrivRaw.size="
            << pqPrivRaw.size();

        Signer_Dilithium pqSigner;
        pqSigner.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
        qDebug() << "[NetworkAuthUtils] Signer_Dilithium loaded successfully";

        std::vector<uint8_t> pqSig = pqSigner.sign(
            std::vector<uint8_t>(canonical.begin(), canonical.end())
            );
        qDebug().nospace()
            << "[NetworkAuthUtils] pqSig.size=" << pqSig.size();

        std::string pqSigB64 = FileClientData::base64_encode(pqSig.data(), pqSig.size());

        // 5) Combine both signatures
        std::string combined = edSigB64 + "||" + pqSigB64;
        qDebug().nospace()
            << "[NetworkAuthUtils] combinedSig.len=" << combined.size();

        // 6) Build headers
        std::map<std::string, std::string> hdrs = {
            { "X-Username",  username },
            { "X-Timestamp", timestamp },
            { "X-Signature", combined }
        };

        qDebug().nospace()
            << "[NetworkAuthUtils] makeAuthHeaders RETURN headers: "
               "X-Username=" << hdrs["X-Username"]
            << ", X-Timestamp=" << hdrs["X-Timestamp"]
            << ", X-Signature.len=" << hdrs["X-Signature"].size();
        return hdrs;
    }
    catch (const std::exception& ex) {
        qDebug().nospace()
            << "[NetworkAuthUtils] ERROR in makeAuthHeaders: " << ex.what();
        throw;  // re-throw so caller sees the exception
    }
}
}
