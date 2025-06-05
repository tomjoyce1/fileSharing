// FileShareHandler.cpp
#include "FileShareHandler.h"
#include "../config.h"
#include <nlohmann/json.hpp>
#include <QMetaObject>
#include <QDebug>
#include <sodium.h>
#include <openssl/rand.h>
#include "../utils/networking/asiosslclient.h"

using json = nlohmann::json;

FileShareHandler::FileShareHandler(ClientStore* s, QObject* parent)
    : QObject(parent), m_store(s)
{
    qDebug() << "[FileShareHandler] Constructor called; this =" << this;
}

// Called from QML: shareFile(fileId, username)
void FileShareHandler::shareFile(qulonglong fileId,
                                 const QString& targetUserQ)
{
    qDebug() << "[FileShareHandler] shareFile() invoked from QML"
             << " fileId =" << fileId
             << " targetUser =" << targetUserQ;
    // Spin the heavy crypto / I/O in a background thread
    HandlerUtils::runAsync([=]() {
        processShare(fileId, targetUserQ.toStdString());
    });
}

//───────────────────────────────────────────────────────────────────────────────
//                      Actual work happens here
//───────────────────────────────────────────────────────────────────────────────
void FileShareHandler::processShare(qulonglong fileId,
                                    const std::string& targetUser)
{
    qDebug() << "[processShare] Entered. fileId =" << fileId
             << " targetUser =" << QString::fromStdString(targetUser);

    // ─── 0. Pull current user + keys from store ──────────────────────────────
    auto maybeUser = m_store->getUser();
    if (!maybeUser.has_value()) {
        qWarning() << "[processShare] ERROR: No logged-in user in ClientStore";
        emit shareResult("Error", "Not logged-in");
        return;
    }
    const auto& me      = *maybeUser;
    const auto& myUname = me.username;
    const auto& myPriv  = me.fullBundle;
    qDebug() << "[processShare] Current user =" << QString::fromStdString(myUname);

    // Prevent sharing with self
    if (myUname == targetUser) {
        qWarning() << "[processShare] ERROR: Attempt to share with self";
        emit shareResult("Error", "Cannot share with yourself");
        return;
    }

    // ─── 1. Look up FileClientData; must own the file ─────────────────────────
    FileClientData* fcdPtr = m_store->getFileData(fileId);
    if (!fcdPtr) {
        QString msg = QString("No local FileClientData for file_id=%1").arg(fileId);
        qWarning() << "[processShare] ERROR:" << msg;
        emit shareResult("Error", msg);
        return;
    }
    const FileClientData& fcd = *fcdPtr;
    qDebug() << "[processShare] Found FileClientData:";
    qDebug() << "   filename    =" << QString::fromStdString(fcd.filename);
    qDebug() << "   local FEK   =" << "(32 bytes)";
    qDebug() << "   local MEK   =" << "(32 bytes)";
    qDebug() << "   file_nonce  =" << QString::fromStdString(
        FileClientData::base64_encode(fcd.file_nonce.data(),
                                      fcd.file_nonce.size()));
    qDebug() << "   metadata_nonce =" << QString::fromStdString(
        FileClientData::base64_encode(fcd.metadata_nonce.data(),
                                      fcd.metadata_nonce.size()));

    // ─── 2. Fetch Bob’s key bundle ────────────────────────────────────────────
    std::string errFetch;
    qDebug() << "[processShare] Fetching public key bundle for"
             << QString::fromStdString(targetUser);
    auto maybeBobPub = fetchPublicBundle(targetUser, errFetch);
    if (!maybeBobPub.has_value()) {
        QString msg = QString("Key-bundle fetch failed: %1")
                          .arg(QString::fromStdString(errFetch));
        qWarning() << "[processShare] ERROR:" << msg;
        emit shareResult("Error", msg);
        return;
    }
    const KeyBundle& bobPub = *maybeBobPub;
    qDebug() << "[processShare] Obtained Bob’s public bundle:";
    qDebug() << "   X25519 public key (raw, hex) ="
             << QByteArray::fromRawData(
                    reinterpret_cast<const char*>(bobPub.getX25519Pub().data()),
                    static_cast<int>(bobPub.getX25519Pub().size())
                    ).toHex();

    // ─── 3. Ephemeral X25519 → sharedSecret ─────────────────────────────────
    Kem_Ecdh eph;
    eph.keygen();
    std::vector<uint8_t> ephPub  = eph.pub();
    std::vector<uint8_t> ephPriv = eph.getSecretKey();
    qDebug() << "[processShare] Generated ephemeral X25519 keys:";
    qDebug() << "   ephPub  (raw, hex) ="
             << QByteArray::fromRawData(
                    reinterpret_cast<const char*>(ephPub.data()),
                    static_cast<int>(ephPub.size())
                    ).toHex();
    qDebug() << "   ephPriv (hidden)  (32 bytes)";

    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    int dhRet = crypto_scalarmult(shared.data(),
                                  ephPriv.data(),
                                  bobPub.getX25519Pub().data());
    if (dhRet != 0) {
        qWarning() << "[processShare] ERROR: crypto_scalarmult returned" << dhRet;
        emit shareResult("Error", "ECDH failed");
        return;
    }
    qDebug() << "[processShare] Derived shared secret (32 bytes, hex) ="
             << QByteArray::fromRawData(
                    reinterpret_cast<const char*>(shared.data()),
                    static_cast<int>(shared.size())
                    ).toHex();

    // ─── 4. Wrap FEK & MEK under sharedSecret ───────────────────────────────
    auto wrapKey = [&](const std::array<uint8_t,32>& key32,
                       std::string& outCtB64,
                       std::string& outIvB64) -> bool
    {
        Symmetric::Ciphertext c;
        try {
            /* encrypt with the *raw* shared-secret */
            c = Symmetric::encrypt(
                std::vector<uint8_t>(key32.begin(), key32.end()),
                shared                     // <-- no SHA-256, just use it
                );
        } catch (const std::exception& ex) {
            qWarning() << "[processShare] ERROR: Symmetric::encrypt() threw:"
                       << ex.what();
            return false;
        }

        outCtB64 = FileClientData::base64_encode(c.data.data(), c.data.size());
        outIvB64 = FileClientData::base64_encode(c.iv.data(),   c.iv.size());
        return true;
    };


    std::string encFekB64, ivFekB64, encMekB64, ivMekB64;
    if (!wrapKey(fcd.fek, encFekB64, ivFekB64)) {
        emit shareResult("Error", "Failed to wrap FEK");
        return;
    }
    if (!wrapKey(fcd.mek, encMekB64, ivMekB64)) {
        emit shareResult("Error", "Failed to wrap MEK");
        return;
    }

    // ─── 5. Build JSON body exactly as server expects ────────────────────────
    nlohmann::ordered_json body;           // not plain `json`

    body["file_id"]              = static_cast<uint64_t>(fileId);
    body["shared_with_username"] = targetUser;
    body["encrypted_fek"]        = encFekB64;
    body["encrypted_fek_nonce"]  = ivFekB64;
    body["encrypted_mek"]        = encMekB64;
    body["encrypted_mek_nonce"]  = ivMekB64;
    body["ephemeral_public_key"] = FileClientData::base64_encode(
        ephPub.data(), ephPub.size());
    body["file_content_nonce"]   = FileClientData::base64_encode(
        fcd.file_nonce.data(), fcd.file_nonce.size());
    body["metadata_nonce"]       = FileClientData::base64_encode(
        fcd.metadata_nonce.data(), fcd.metadata_nonce.size());

    QString bodyPretty = QString::fromStdString(body.dump(2));
    qDebug() << "[processShare] JSON request body:";
    qDebug().noquote() << bodyPretty;

    // ─── 6. POST /api/fs/share ───────────────────────────────────────────────
    std::string errSend;
    qDebug() << "[processShare] Calling sendShareRequest(...)";
    bool ok = sendShareRequest(body, errSend);
    if (!ok) {
        QString msg = QString("Share request failed: %1").arg(QString::fromStdString(errSend));
        qWarning() << "[processShare] ERROR:" << msg;
        emit shareResult("Error", msg);
        return;
    }

    // ─── 7. Success → notify QML ─────────────────────────────────────────────
    qDebug() << "[processShare] Share succeeded!";
    QMetaObject::invokeMethod(
        this,
        [=]() {
            emit shareResult("Success", "File shared successfully");
        },
        Qt::QueuedConnection
        );
}

//───────────────────────────────────────────────────────────────────────────────
//     Helper: fetch public bundle for `uname` (POST /api/identity/get-bundle)
//───────────────────────────────────────────────────────────────────────────────
std::optional<KeyBundle>
FileShareHandler::fetchPublicBundle(const std::string& uname,
                                    std::string& outErr) const
{
    qDebug() << "[fetchPublicBundle] Called for username =" << QString::fromStdString(uname);

    // Build request body and sign it
    json jBody = { {"username", uname} };
    std::string bodyStr = jBody.dump();
    qDebug() << "[fetchPublicBundle] bodyString =" << QString::fromStdString(bodyStr);

    // Grab our credentials
    auto maybeUser = m_store->getUser();
    if (!maybeUser.has_value()) {
        outErr = "ClientStore has no user";
        qWarning() << "[fetchPublicBundle] ERROR:" << QString::fromStdString(outErr);
        return std::nullopt;
    }
    const auto& me = *maybeUser;
    qDebug() << "[fetchPublicBundle] Signing request as =" << QString::fromStdString(me.username);

    auto headers = NetworkAuthUtils::makeAuthHeaders(
        me.username, me.fullBundle,
        "POST", "/api/keyhandler/getbundle", bodyStr);
    headers["Content-Type"] = "application/json";

    // Log all headers
    qDebug() << "[fetchPublicBundle] Request headers:";
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        qDebug() << "   " << QString::fromStdString(it->first)
                 << ": " << QString::fromStdString(it->second);
    }

    // Send
    HttpRequest  req(HttpRequest::Method::POST,
                    "/api/keyhandler/getbundle",
                    bodyStr, headers);
    AsioSslClient cli;
    HttpResponse resp = cli.sendRequest(req);

    qDebug() << "[fetchPublicBundle] HTTP status code =" << resp.statusCode;
    qDebug() << "[fetchPublicBundle] HTTP response body ="
             << QString::fromStdString(resp.body);

    if (resp.statusCode != 200) {
        outErr = "HTTP " + std::to_string(resp.statusCode);
        return std::nullopt;
    }

    // Parse JSON
    json jResp;
    try {
        jResp = json::parse(resp.body);
    } catch (const std::exception& ex) {
        outErr = std::string("Invalid JSON: ") + ex.what();
        qWarning() << "[fetchPublicBundle] ERROR: JSON parse failed:"
                   << QString::fromStdString(outErr);
        return std::nullopt;
    }

    if (!jResp.contains("key_bundle")) {
        outErr = "Response does not contain key_bundle field";
        qWarning() << "[fetchPublicBundle] ERROR:" << QString::fromStdString(outErr);
        return std::nullopt;
    }

    // Construct KeyBundle
    try {
        std::string kbJsonStr = jResp["key_bundle"].dump();
        qDebug() << "[fetchPublicBundle] key_bundle JSON ="
                 << QString::fromStdString(kbJsonStr);
        return KeyBundle::fromJson(kbJsonStr);
    } catch (const std::exception& ex) {
        outErr = std::string("KeyBundle::fromJson failed: ") + ex.what();
        qWarning() << "[fetchPublicBundle] ERROR:" << QString::fromStdString(outErr);
        return std::nullopt;
    }
}

//───────────────────────────────────────────────────────────────────────────────
// Helper: POST /api/fs/share
//───────────────────────────────────────────────────────────────────────────────
bool FileShareHandler::sendShareRequest(const nlohmann::ordered_json& body,
                                        std::string& outErr) const
{
    qDebug() << "[sendShareRequest] Called";

    // Dump JSON
    std::string bodyStr = body.dump();
    qDebug() << "[sendShareRequest] bodyString =" << QString::fromStdString(bodyStr);

    // Grab our credentials
    auto maybeUser = m_store->getUser();
    if (!maybeUser.has_value()) {
        outErr = "ClientStore has no user for share";
        qWarning() << "[sendShareRequest] ERROR:" << QString::fromStdString(outErr);
        return false;
    }
    const auto& me = *maybeUser;
    qDebug() << "[sendShareRequest] Signed by =" << QString::fromStdString(me.username);

    // Create signed headers
    auto headers = NetworkAuthUtils::makeAuthHeaders(
        me.username, me.fullBundle,
        "POST", "/api/fs/share", bodyStr
        );
    headers["Content-Type"] = "application/json";

    // Log headers
    qDebug() << "[sendShareRequest] Request headers:";
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        qDebug() << "   " << QString::fromStdString(it->first)
                 << ": " << QString::fromStdString(it->second);
    }

    // Build and send
    HttpRequest  req(HttpRequest::Method::POST, "/api/fs/share",
                    bodyStr, headers);
    AsioSslClient cli;
    HttpResponse  resp = cli.sendRequest(req);

    qDebug() << "[sendShareRequest] HTTP status =" << resp.statusCode;
    qDebug() << "[sendShareRequest] HTTP body =" << QString::fromStdString(resp.body);

    if (resp.statusCode == 201) {
        return true;
    }

    // Try to extract “message” from JSON
    try {
        json jr = json::parse(resp.body);
        if (jr.contains("message")) {
            outErr = jr["message"].get<std::string>();
        }
    } catch (...) { }

    if (outErr.empty()) {
        outErr = "HTTP " + std::to_string(resp.statusCode);
    }
    return false;
}
