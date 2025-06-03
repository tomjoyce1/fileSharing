#pragma once
#include <QObject>
#include <QStringList>
#include <nlohmann/json.hpp>
#include "../utils/ClientStore.h"
#include "../utils/crypto/FileClientData.h"
#include "../utils/crypto/KeyBundle.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/crypto/Signer_Ed.h"
#include "../utils/crypto/Signer_Dilithium.h"
#include "../utils/crypto/Hash.h"
#include "../utils/NetworkAuthUtils.h"
#include "../utils/HandlerUtils.h"
#include "../utils/networking/AsioHttpClient.h"
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResponse.h"

/**
 * FileUploadHandler
 *
 * QML calls uploadFiles(fileUrls).  For each file:
 *   1. read bytes, 2. build FileClientData (FEK/MEK/IVs),
 *   3. encrypt file/metadata,
 *   4. base64‐encode ciphertexts,
 *   5. compute sha256 hashes, sign with Ed25519 + Dilithium,
 *   6. build JSON, build dual‐signature headers, POST /api/fs/upload,
 *   7. on success, store FileClientData in ClientStore.
 *
 *   Chris C++ Requirements:
 *   - Classes and Objects (instance in main.cpp)
 */
class FileUploadHandler : public QObject {
    Q_OBJECT

public:
    explicit FileUploadHandler(ClientStore* store, QObject* parent = nullptr);
    ~FileUploadHandler() override = default;

    /** Invoked from QML: uploads all files in the list */
    Q_INVOKABLE void uploadFiles(const QStringList& fileUrls);

signals:
    /** For each file, emits Success/Error/Exception + message */
    void uploadResult(const QString& title, const QString& message);

private:
    /** Process one file.  Returns new file_id or 0 on failure. */
    uint64_t processSingleFile(const std::string& localPath);

    /** Read entire file into vector<uint8_t>. */
    std::vector<uint8_t> readFileBytes(const std::string& path);

    /** Given username, fileB64, metaB64, return "username|sha256(file)|sha256(meta)" */
    std::string buildSignatureInput(const std::string& uname,
                                    const std::string& fileB64,
                                    const std::string& metaB64);

    ClientStore* store;
    std::string username;
    KeyBundle keybundle;
};
