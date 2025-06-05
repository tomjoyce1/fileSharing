#pragma once
#include <QObject>
#include <QString>
#include "../utils/ClientStore.h"
#include "../utils/crypto/FileClientData.h"
#include "../utils/crypto/Kem_Ecdh.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/NetworkAuthUtils.h"
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResponse.h"
#include "../utils/HandlerUtils.h"

/**
 * FileShareHandler
 *
 *  shareFile(fileId, "bob")  →
 *      • look up FileClientData (must be owner)
 *      • GET Bob’s public key bundle
 *      • X25519(EphPriv, BobPub)  → sharedSecret
 *      • AES-CTR(sharedSecret) wrap FEK / MEK
 *      • POST /api/fs/share
 *
 * Emits shareResult(title, message) so QML can show a toast/snackbar.
 */
class FileShareHandler : public QObject {
    Q_OBJECT
public:
    explicit FileShareHandler(ClientStore* store, QObject* parent = nullptr);

    /** Invoked from QML: share fileId with username */
    Q_INVOKABLE void shareFile(qulonglong fileId,
                               const QString& targetUsername);

signals:
    void shareResult(const QString& title, const QString& message);

private:
    void processShare(qulonglong fileId,
                      const std::string& targetUsername);

    // Helpers
    std::optional<KeyBundle> fetchPublicBundle(const std::string& uname,
                                               std::string& outErr) const;
    bool sendShareRequest(const nlohmann::ordered_json& body,
                          std::string& outErr) const;

    ClientStore* m_store;
};
