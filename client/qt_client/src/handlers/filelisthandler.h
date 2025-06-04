#pragma once

#include <QObject>
#include <QString>
#include <QDateTime>
#include <QVariant>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

#include "../utils/ClientStore.h"       // Your class that stores UserInfo + FileClientData
#include "../utils/crypto/KeyBundle.h"  // Holds Ed25519, Dilithium, X25519 keys (public & private)
#include "../utils/crypto/Symmetric.h"  // AES-256-CTR decrypt
#include "../utils/crypto/FileClientData.h" // Contains FEK/MEK/nonces + to/from JSON + base64 helpers

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

    // QML-callable methods:
    // - Fetch page=1 of ALL files
    // - Fetch page=1 of OWNED files only
    // - Fetch page=1 of SHARED files only
    Q_INVOKABLE void listAllFiles(int page = 1);
    Q_INVOKABLE void listOwnedFiles(int page = 1);
    Q_INVOKABLE void listSharedFiles(int page = 1);

signals:
    // Emitted after a page of files is fetched & decrypted.
    // Each QVariantMap has keys: file_id, filename, size, modified, is_owner, is_shared, shared_from.
    void filesLoaded(const QVariantList& decryptedFiles);

    // Emitted if something goes wrong (e.g. network error, JSON parse error, decryption failure).
    void errorOccurred(const QString& message);

private:
    // Core worker: does the signed POST → JSON parse → decrypt loop
    void fetchPage(int page, bool onlyOwned, bool onlyShared);

    // Given one element of the server’s fileData[], decrypt its metadata & fill a DecryptedFile.
    std::optional<DecryptedFile> parseAndDecryptSingle(const nlohmann::json& singleFileJson);

    // If a file is shared (is_owner==false), unwrap FEK & MEK via X25519 ECDH + AES-CTR.
    // Returns: pair<rawFEK, rawMEK> (each a 32-byte vector).
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    unwrapKeysFromJson(const nlohmann::json& singleFileJson, const KeyBundle& privBundle);

private:
    ClientStore*    m_store;      // Provides getUser() and getFileData(file_id)
    QString         m_username;   // Current logged-in username (UTF-8)
    KeyBundle       m_privBundle; // User’s full KeyBundle (has private X25519, Ed25519, Dilithium)
};
