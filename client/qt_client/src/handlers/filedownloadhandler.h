#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <nlohmann/json.hpp>
#include "../utils/ClientStore.h"
#include "../utils/crypto/FileClientData.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/crypto/Signer_Ed.h"
#include "../utils/crypto/Signer_Dilithium.h"
#include "../utils/crypto/Hash.h"
#include "../utils/crypto/DerUtils.h"
#include "../utils/NetworkAuthUtils.h"
#include "../utils/HandlerUtils.h"
#include "../utils/networking/AsioHttpClient.h"
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResponse.h"

/**
 * FileDownloadHandler
 *
 * 1. POST /api/fs/download {file_id}
 * 2. Verify Ed25519 + Dilithium signatures returned by the server
 * 3. Decrypt file & metadata with FEK/MEK from ClientStore (owner-only)
 * 4. Emit Qt signals back to QML: success / error / plaintext ready
 */
class FileDownloadHandler : public QObject {
    Q_OBJECT

public:
    explicit FileDownloadHandler(ClientStore *store, QObject *parent = nullptr);
    ~FileDownloadHandler() override = default;

    Q_INVOKABLE void downloadFile(qulonglong fileId);
    Q_INVOKABLE bool saveToFile(const QString &path, const QByteArray &data);
    bool saveToDownloads(const QString& fileName, const QByteArray& data);

signals:
    //title = "Success" | "Error" | "Exception"; message = user-friendly
    void downloadResult(const QString &title, const QString &message);

    // Used for toast notifcation (not implemented yet
    void fileReady(qulonglong fileId, const QString &fileName, const QByteArray &plainData);

private:
    // Background worker for a single file
    void processSingleFile(qulonglong fileId);

    // Re-computes canonical string and verify both signatures
    bool verifySignatures(const std::string &username, const std::string &fileB64, const std::string &metaB64, const std::string &edSigB64, const std::string &pqSigB64, const KeyBundle &pubBundle,std::string &outError);

    ClientStore *store;
};
