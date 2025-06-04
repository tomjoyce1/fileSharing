#include "DownloadFileHandler.h"

DownloadFileHandler::DownloadFileHandler(ClientStore* store, QObject* parent)
    : QObject(parent)
    , store(store)
{
}

void DownloadFileHandler::downloadFile(int fileId)
{
    DownloadFileHandler* self = this;

    // Run on a background thread so UI/QML doesn’t freeze
    HandlerUtils::runAsync([self, fileId] {
        bool success = false;
        QString qTitle, qMsg;

        try {
            success = self->processSingleFile(fileId);
            if (success) {
                qTitle = "Success";
                qMsg = QString("Downloaded file ID %1 to your Desktop").arg(fileId);
            } else {
                qTitle = "Error";
                qMsg = QString("Failed to download file ID %1").arg(fileId);
            }
        }
        catch (const std::exception& ex) {
            success = false;
            qTitle = "Exception";
            qMsg = QString("Exception while downloading %1: %2")
                       .arg(fileId)
                       .arg(QString::fromStdString(ex.what()));
        }

        // Emit result back on the main (GUI) thread
        QMetaObject::invokeMethod(
            self,
            [self, success, qTitle, qMsg]() { emit self->downloadResult(qTitle, qMsg); },
            Qt::QueuedConnection
            );
    });
}

bool DownloadFileHandler::processSingleFile(int fileId)
{
    // 1) Get logged‐in user and their KeyBundle
    auto maybeUser = store->getUser();
    if (!maybeUser.has_value()) {
        throw std::runtime_error("No logged-in user when trying to download");
    }
    const auto& userInfo  = *maybeUser;
    const auto& keybundle = userInfo.fullBundle;
    const auto& username  = userInfo.username;

    // 2) Get local FileClientData for this fileId
    FileClientData* fcdPtr = store->getFileData(static_cast<uint64_t>(fileId));
    if (!fcdPtr) {
        qWarning() << "[DownloadFileHandler] No local FileClientData for file_id=" << fileId;
        return false;
    }
    // Make a local copy so we can freely manipulate
    FileClientData fcd = *fcdPtr;

    // 3) Build JSON body for /api/fs/download
    nlohmann::ordered_json jbody;
    jbody["file_id"] = fileId;
    std::string bodyString = jbody.dump();

    // 4) Create dual‐signature auth headers exactly like in FileUploadHandler
    auto headers = NetworkAuthUtils::makeAuthHeaders(
        username,
        keybundle,
        "POST",
        "/api/fs/download",
        bodyString
        );

    // 5) Send the HTTP request
    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/fs/download",
        bodyString,
        headers
        );
    AsioHttpClient client;
    client.init("");  // pulls from Config::instance().serverHost / port

    HttpResponse resp = client.sendRequest(req);
    if (resp.statusCode != 200) {
        qWarning() << "[DownloadFileHandler] HTTP status code =" << resp.statusCode;
        return false;
    }

    // 6) Parse the JSON response
    nlohmann::json respJson;
    try {
        respJson = nlohmann::json::parse(resp.body);
    }
    catch (const std::exception& ex) {
        qWarning() << "[DownloadFileHandler] JSON parse error:" << ex.what();
        return false;
    }

    // 7) Extract required fields
    if (!respJson.contains("file_content") ||
        !respJson.contains("metadata") ||
        !respJson.contains("pre_quantum_signature") ||
        !respJson.contains("post_quantum_signature") ||
        !respJson.contains("owner_username"))
    {
        qWarning() << "[DownloadFileHandler] Missing fields in server response.";
        return false;
    }

    std::string fileB64       = respJson.at("file_content").get<std::string>();
    std::string metaB64       = respJson.at("metadata").get<std::string>();
    std::string edSigB64      = respJson.at("pre_quantum_signature").get<std::string>();
    std::string pqSigB64      = respJson.at("post_quantum_signature").get<std::string>();
    std::string ownerUsername = respJson.at("owner_username").get<std::string>();
    bool        isOwner       = respJson.value("is_owner", false);

    // 8) Base64‐decode everything
    std::vector<uint8_t> encFileData = base64Decode(fileB64);
    std::vector<uint8_t> encMetaData = base64Decode(metaB64);
    std::vector<uint8_t> edSigRaw    = base64Decode(edSigB64);
    std::vector<uint8_t> pqSigRaw    = base64Decode(pqSigB64);

    if (encFileData.empty() || encMetaData.empty() || edSigRaw.empty() || pqSigRaw.empty()) {
        qWarning() << "[DownloadFileHandler] Decoded buffers are empty.";
        return false;
    }

    // 9) Compute SHA‐256 over the ciphertexts → hex
    std::vector<uint8_t> fileHash = Hash::sha256(encFileData);
    std::vector<uint8_t> metaHash = Hash::sha256(encMetaData);
    std::string fileHashHex = bytesToHex(fileHash);
    std::string metaHashHex = bytesToHex(metaHash);

    // 10) Reconstruct the “signed” message: "<ownerUsername>|<fileHashHex>|<metaHashHex>"
    std::ostringstream oss;
    oss << ownerUsername << "|" << fileHashHex << "|" << metaHashHex;
    std::string sigInput = oss.str();
    std::vector<uint8_t> msgBytes(sigInput.begin(), sigInput.end());

    // 11) Determine which public‐key bundle to use for verification:
    KeyBundle ownerPubBundle;
    if (isOwner) {
        // If we are the owner, we already have our own publicBundle in memory.
        ownerPubBundle = userInfo.publicBundle;
    } else {
        // If NOT the owner, we must fetch the owner's public keys.
        // You need to implement this method in ClientStore (or call a server endpoint + cache it).
        auto maybeOwnerPub = store->getPublicBundleForUsername(ownerUsername);
        if (!maybeOwnerPub.has_value()) {
            qWarning() << "[DownloadFileHandler] Could not fetch owner’s public bundle for '"
                       << QString::fromStdString(ownerUsername) << "'";
            return false;
        }
        ownerPubBundle = *maybeOwnerPub;
    }

    // 12) Base64‐decode owner’s Ed25519 pubkey & Dilithium pubkey
    std::vector<uint8_t> ownerEdPubRaw  = ownerPubBundle.getEd25519Pub();
    std::vector<uint8_t> ownerPqPubRaw  = ownerPubBundle.getDilithiumPub();

    if (ownerEdPubRaw.empty() || ownerPqPubRaw.empty()) {
        qWarning() << "[DownloadFileHandler] Owner’s public key raw buffers are empty.";
        return false;
    }

    // 13) Verify Ed25519
    bool okEd = verifyWithEd25519(ownerEdPubRaw, msgBytes, edSigRaw);
    if (!okEd) {
        qWarning() << "[DownloadFileHandler] Ed25519 signature verification failed.";
        return false;
    }

    // 14) Verify Dilithium
    bool okPq = verifyWithDilithium(ownerPqPubRaw, msgBytes, pqSigRaw);
    if (!okPq) {
        qWarning() << "[DownloadFileHandler] Dilithium signature verification failed.";
        return false;
    }

    // 15) Decrypt metadata ciphertext under (fcd.mek + fcd.metadata_nonce)
    std::vector<uint8_t> metaCipherBytes = std::move(encMetaData);
    std::vector<uint8_t> metaIv(fcd.metadata_nonce.begin(), fcd.metadata_nonce.end());

    // Decrypt under (MEK, metadata_nonce):
    std::vector<uint8_t> mekVec(fcd.mek.begin(), fcd.mek.end());
    Symmetric::Plaintext plainMeta = Symmetric::decrypt(
        metaCipherBytes,
        mekVec,
        metaIv
        );
    std::vector<uint8_t> plainMetaBytes = std::move(plainMeta.data);

    if (plainMetaBytes.empty()) {
        qWarning() << "[DownloadFileHandler] Metadata decryption produced empty result.";
        return false;
    }

    // 16) Parse decrypted metadata JSON → { "filename", "filesize" }
    std::string metaJsonStr(plainMetaBytes.begin(), plainMetaBytes.end());
    nlohmann::json metaJson;
    try {
        metaJson = nlohmann::json::parse(metaJsonStr);
    }
    catch (const std::exception& ex) {
        qWarning() << "[DownloadFileHandler] Failed to parse decrypted metadata JSON: " << ex.what();
        return false;
    }

    if (!metaJson.contains("filename") || !metaJson.contains("filesize")) {
        qWarning() << "[DownloadFileHandler] Metadata JSON missing filename/filesize.";
        return false;
    }
    std::string filename = metaJson.at("filename").get<std::string>();
    // size_t    filesize = metaJson.at("filesize").get<size_t>(); // if you need to double‐check

    // Build ciphertext + iv manually
    std::vector<uint8_t> fileCipherBytes = std::move(encFileData);
    std::vector<uint8_t> fileIv(fcd.file_nonce.begin(), fcd.file_nonce.end());

    // Decrypt under (FEK, file_nonce):
    std::vector<uint8_t> fekVec(fcd.fek.begin(), fcd.fek.end());
    Symmetric::Plaintext plainFile = Symmetric::decrypt(
        fileCipherBytes,
        fekVec,
        fileIv
        );
    std::vector<uint8_t> plainFileBytes = std::move(plainFile.data);

    if (plainFileBytes.empty()) {
        qWarning() << "[DownloadFileHandler] File decryption produced empty result.";
        return false;
    }

    // 18) Write plaintext to ~/Desktop/<filename>
    QString desktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    if (desktopPath.isEmpty()) {
        qWarning() << "[DownloadFileHandler] Could not resolve Desktop location.";
        return false;
    }
    QString outFilePath = QDir(desktopPath).filePath(QString::fromStdString(filename));

    std::ofstream outFile(outFilePath.toStdString(), std::ios::binary);
    if (!outFile.good()) {
        qWarning() << "[DownloadFileHandler] Failed to open output file for writing: " << outFilePath;
        return false;
    }
    outFile.write(reinterpret_cast<const char*>(plainFileBytes.data()),
                  static_cast<std::streamsize>(plainFileBytes.size()));
    outFile.close();

    // 19) Everything succeeded
    return true;
}
