#pragma once

#include <QObject>
#include <QStringList>
#include <future>            // for std::async
#include <mutex>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

// Include exactly the crypto headers you need:
#include "../utils/crypto/FileClientData.h"      // brings in CryptoBase.h transitively
#include "../utils/crypto/KeyBundle.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/crypto/Signer_Ed.h"
#include "../utils/crypto/Signer_Dilithium.h"
#include "../utils/crypto/Kem_Ecdh.h"

// Include your HTTP client headers:
#include "../utils/networking/AsioHttpClient.h"
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResponse.h"

// Include ClientStore
#include "../utils/ClientStore.h"

using json = nlohmann::json;

/**
 * FileUploadHandler
 *
 * Handles file uploads from QML.  For each file:
 *  1. Read bytes from disk.
 *  2. Create a FileClientData (FEK, MEK, nonces).
 *  3. Encrypt file & metadata with Symmetric::encrypt(plaintext, key).
 *  4. Base64‐encode ciphertext & IV.
 *  5. Sign with Signer_Ed and Signer_Dilithium.
 *  6. POST to /api/fs/upload using AsioHttpClient.
 *  7. Store FileClientData in ClientStore on success.
 */
class FileUploadHandler : public QObject {
    Q_OBJECT

public:
    explicit FileUploadHandler(ClientStore* store, QObject* parent = nullptr);
    ~FileUploadHandler() override = default;

    // QML calls this method with a list of file URLs to upload
    Q_INVOKABLE void uploadFiles(const QStringList& fileUrls);

signals:
    // Emitted once per file, with a title ("Success"/"Error"/"Exception") and a message
    void uploadResult(const QString& title, const QString& message);

private:
    // Process one file; returns the new file_id on success, or 0 on failure
    uint64_t processSingleFile(const std::string& localPath);

    // Reads an entire file from disk into a vector<uint8_t>
    std::vector<uint8_t> readFileBytes(const std::string& path);

    // Builds the signature input string: "username|fileB64|metaB64"
    std::string buildSignatureInput(const std::string& uname,
                                    const std::string& fileB64,
                                    const std::string& metaB64);

    ClientStore*    m_store;       // Not owned; pointer to the global store
    std::string     m_username;    // Loaded from ClientStore
    KeyBundle       m_keybundle;   // Loaded from ClientStore
};
