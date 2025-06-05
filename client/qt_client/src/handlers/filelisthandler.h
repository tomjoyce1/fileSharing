#pragma once

#include <QObject>
#include <QString>
#include <QDateTime>
#include <QVariant>
#include <vector>
#include <optional>
#include <map>
#include <nlohmann/json.hpp>
#include "../utils/ClientStore.h"
#include "../utils/crypto/KeyBundle.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/crypto/FileClientData.h"

/**
 * A simplified struct representing one file’s decrypted metadata.
 */
struct DecryptedFile {
    uint64_t    file_id;
    QString     filename;
    uint64_t    size_bytes;
    QDateTime   upload_timestamp;
    bool        is_owner;
    bool        is_shared;
    QString     shared_from;  // If shared, the username of the sharer (optional)
};

class FileListHandler : public QObject {
    Q_OBJECT

public:
    explicit FileListHandler(ClientStore* store, QObject* parent = nullptr);

    Q_INVOKABLE void listAllFiles(int page = 1);
    Q_INVOKABLE void listOwnedFiles(int page = 1);
    Q_INVOKABLE void listSharedFiles(int page = 1);

    // file delete goes into this handler for simplicity
    Q_INVOKABLE void deleteFile(qulonglong fileId);

signals:
    // Emitted after a page of files is fetched & decrypted.
    // Each QVariantMap has keys: file_id, filename, size, modified, is_owner, is_shared, shared_from.
    void filesLoaded(const QVariantList& decryptedFiles);

    // Emitted if something goes wrong (e.g. network error, JSON parse error, decryption failure).
    void errorOccurred(const QString& message);

    void deleteResult(const QString& title, const QString& message);

private:
    void fetchPage(int page, bool onlyOwned, bool onlyShared);
    std::string buildPostBody(int page) const;
    std::optional<nlohmann::json> sendListRequest(const std::string& bodyStr, const std::map<std::string, std::string>& headers, QString& outError);

    // Given the “fileData” array, filter (owned/shared) & decrypt all entries to QVariantList
    QVariantList processFileArray(const nlohmann::json& fileArray, bool onlyOwned, bool onlyShared);

    // Decrypt metadata & build a QVariantMap
    std::optional<QVariantMap> decryptSingleToVariant(const nlohmann::json& singleFileJson);

    std::optional<DecryptedFile> parseAndDecryptSingle(const nlohmann::json& singleFileJson);

    // Unwrap FEK/MEK via X25519 + AES-CTR
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> unwrapKeysFromJson(const nlohmann::json& singleFileJson, const KeyBundle& privBundle);

private:
    ClientStore*    m_store;
    QString         m_username;
    KeyBundle       m_privBundle;
};
