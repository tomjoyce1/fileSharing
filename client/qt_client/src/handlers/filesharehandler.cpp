// FileShareHandler.cpp
#include "FileShareHandler.h"
#include "../config.h"
#include <nlohmann/json.hpp>
#include <QMetaObject>
#include <QDebug>
#include <sodium.h>
#include <openssl/rand.h>
#include "../utils/networking/asiosslclient.h"
#include "../utils/crypto/hash.h"

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

void FileShareHandler::processShare(qulonglong fileId, const std::string &targetUser)
{
    qDebug() << "[processShare] Entered. fileId =" << fileId
             << " targetUser =" << QString::fromStdString(targetUser);

    // ─── 0. Pull current user + keys from store ──────────────────────────────
    auto maybeUser = m_store->getUser();
    if (!maybeUser.has_value()) {
        qWarning() << "[processShare] ERROR: No logged‑in user in ClientStore";
        emit shareResult("Error", "Not logged‑in");
        return;
    }
    const auto &me      = *maybeUser;
    const auto &myUname = me.username;
    qDebug() << "[processShare] Current user =" << QString::fromStdString(myUname);

    // Prevent sharing with self
    if (myUname == targetUser) {
        qWarning() << "[processShare] ERROR: Attempt to share with self";
        emit shareResult("Error", "Cannot share with yourself");
        return;
    }

    // ─── 1. Look up FileClientData; must own the file ─────────────────────────
    FileClientData *fcdPtr = m_store->getFileData(fileId);
    if (!fcdPtr) {
        QString msg = QString("No local FileClientData for file_id=%1").arg(fileId);
        qWarning() << "[processShare] ERROR:" << msg;
        emit shareResult("Error", msg);
        return;
    }
    const FileClientData &fcd = *fcdPtr;

    // ─── 2. Fetch Bob’s key bundle ────────────────────────────────────────────
    std::string errFetch;
    auto maybeBobPub = fetchPublicBundle(targetUser, errFetch);
    if (!maybeBobPub.has_value()) {
        QString msg = QString("Key‑bundle fetch failed: %1").arg(QString::fromStdString(errFetch));
        emit shareResult("Error", msg);
        return;
    }
    const KeyBundle &bobPub = *maybeBobPub;

    // ─── 3. Ephemeral X25519 → sharedSecret ─────────────────────────────────
    Kem_Ecdh eph;
    eph.keygen();
    std::vector<uint8_t> ephPub  = eph.pub();
    std::vector<uint8_t> ephPriv = eph.getSecretKey();

    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(shared.data(), ephPriv.data(), bobPub.getX25519Pub().data()) != 0) {
        emit shareResult("Error", "ECDH failed");
        return;
    }
    qDebug() << "[processShare] Derived raw secret (32 B) ="
             << QByteArray::fromRawData(reinterpret_cast<const char *>(shared.data()), static_cast<int>(shared.size())).toHex();

    // ─── 3b. **Derive the AES key exactly like Bob: SHA‑256(secret) ** ──────
    std::vector<uint8_t> aesKey = Hash::sha256(shared); // 32‑byte digest
    qDebug() << "[processShare] aesKey = SHA‑256(shared) (32 B) ="
             << QByteArray::fromRawData(reinterpret_cast<const char *>(aesKey.data()), static_cast<int>(aesKey.size())).toHex();

    // ─── 4. Wrap FEK & MEK with aesKey ──────────────────────────────────────
    auto wrapKey = [&](const std::array<uint8_t, 32> &key,
                       std::string &outCtB64,
                       std::string &outIvB64) -> bool {
        try {
            Symmetric::Ciphertext c = Symmetric::encrypt({key.begin(), key.end()}, aesKey);
            outCtB64 = FileClientData::base64_encode(c.data.data(), c.data.size());
            outIvB64 = FileClientData::base64_encode(c.iv.data(), c.iv.size());
            return true;
        } catch (const std::exception &ex) {
            qWarning() << "[processShare] ERROR: encrypt threw:" << ex.what();
            return false;
        }
    };

    std::string encFekB64, ivFekB64, encMekB64, ivMekB64;
    if (!wrapKey(fcd.fek, encFekB64, ivFekB64) || !wrapKey(fcd.mek, encMekB64, ivMekB64)) {
        emit shareResult("Error", "Failed to wrap FEK/MEK");
        return;
    }

    // ─── 5. Build JSON body exactly as server expects ────────────────────────
    nlohmann::ordered_json body;
    body["file_id"]               = static_cast<uint64_t>(fileId);
    body["shared_with_username"]  = targetUser;
    body["encrypted_fek"]         = encFekB64;
    body["encrypted_fek_nonce"]   = ivFekB64;
    body["encrypted_mek"]         = encMekB64;
    body["encrypted_mek_nonce"]   = ivMekB64;
    body["ephemeral_public_key"]  = FileClientData::base64_encode(ephPub.data(), ephPub.size());
    body["file_content_nonce"]    = FileClientData::base64_encode(fcd.file_nonce.data(), fcd.file_nonce.size());
    body["metadata_nonce"]        = FileClientData::base64_encode(fcd.metadata_nonce.data(), fcd.metadata_nonce.size());

    // ─── 6. POST /api/fs/share ───────────────────────────────────────────────
    std::string errSend;
    if (!sendShareRequest(body, errSend)) {
        emit shareResult("Error", QString::fromStdString(errSend));
        return;
    }

    // ─── 7. Success → notify QML ─────────────────────────────────────────────
    emit shareResult("Success", "File shared successfully");
}

//     Helper: fetch public bundle for `uname` (POST /api/identity/get-bundle)
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
