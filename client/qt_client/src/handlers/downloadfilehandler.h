#pragma once

#include <QObject>
#include <QString>
#include <nlohmann/json.hpp>
#include "../utils/ClientStore.h"
#include "../utils/crypto/FileClientData.h"
#include "../utils/crypto/KeyBundle.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/crypto/Signer_Ed.h"
#include "../utils/crypto/Signer_Dilithium.h"
#include "../utils/crypto/Hash.h"
#include "../utils/networking/AsioHttpClient.h"
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResponse.h"
#include "../utils/handlerutils.h"
#include "../utils/NetworkAuthUtils.h"

#include <QStandardPaths>
#include <QDir>
#include <QMetaObject>
#include <QDebug>
#include <fstream>
#include <sstream>

/**
 * DownloadFileHandler
 *
 * Exposes downloadFile(int fileId) to QML.  For each fileId:
 *   1. Fetch encrypted blob + metadata from /api/fs/download (POST).
 *   2. Verify Ed25519 & Dilithium signatures over "<ownerUsername>|<fileHashHex>|<metaHashHex>".
 *   3. Decrypt metadata under local MEK + nonce → JSON {filename, filesize}.
 *   4. Decrypt file contents under local FEK + nonce → plaintext bytes.
 *   5. Write plaintext to ~/Desktop/<filename>.
 *
 * Emits downloadResult(title, message) back to QML.
 */
class DownloadFileHandler : public QObject {
    Q_OBJECT

public:
    explicit DownloadFileHandler(ClientStore* store, QObject* parent = nullptr);
    ~DownloadFileHandler() override = default;

    /** Called from QML: request a download of fileId */
    Q_INVOKABLE void downloadFile(int fileId);

signals:
    /** Emits “Success” or “Error” back to QML */
    void downloadResult(const QString& title, const QString& message);

private:
    /** Orchestrates the entire process. Returns true if successful. */
    bool processSingleFile(int fileId);

    /** Convert a byte vector → lowercase hex string */
    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        static const char* lut = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (uint8_t b : data) {
            out.push_back(lut[b >> 4]);
            out.push_back(lut[b & 0x0F]);
        }
        return out;
    }

    /** Base64‐decode helper (calls into FileClientData) */
    static std::vector<uint8_t> base64Decode(const std::string& s) {
        return FileClientData::base64_decode(s);
    }

    /** Verify an Ed25519 signature (returns true if valid) */
    bool verifyWithEd25519(const std::vector<uint8_t>& pubKeyRaw,
                           const std::vector<uint8_t>& msg,
                           const std::vector<uint8_t>& sig) const
    {
        Signer_Ed verifierEd;
        verifierEd.loadPublicKey(pubKeyRaw.data(), pubKeyRaw.size());
        return verifierEd.verify(msg, sig);
    }

    /** Verify a Dilithium signature (returns true if valid) */
    bool verifyWithDilithium(const std::vector<uint8_t>& pubKeyRaw,
                             const std::vector<uint8_t>& msg,
                             const std::vector<uint8_t>& sig) const
    {
        Signer_Dilithium verifierPQ;
        verifierPQ.loadPublicKey(pubKeyRaw.data(), pubKeyRaw.size());
        return verifierPQ.verify(msg, sig);
    }

private:
    ClientStore* store;
};
