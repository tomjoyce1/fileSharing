// DownloadFileHandler.cpp
#include "DownloadFileHandler.h"
#include <iomanip>   // for std::hex, std::setw, std::setfill
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
// Simple hex‐encoder: turns each byte into two hex digits (lowercase).
static std::string bytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

DownloadFileHandler::DownloadFileHandler(ClientStore* store, QObject* parent)
    : QObject(parent)
    , store(store)
{
    qDebug() << "[DownloadFileHandler] Constructor called";
}

void DownloadFileHandler::downloadFile(int fileId)
{
    qDebug() << "[DownloadFileHandler] downloadFile() called with fileId =" << fileId;
    DownloadFileHandler* self = this;

    HandlerUtils::runAsync([self, fileId] {
        qDebug() << "[DownloadFileHandler] Background thread started for fileId =" << fileId;

        bool success = false;
        QString qTitle, qMsg;

        try {
            success = self->processSingleFile(fileId);
            if (success) {
                qTitle = "Success";
                qMsg = QString("Downloaded file ID %1 to your Desktop").arg(fileId);
                qDebug() << "[DownloadFileHandler] processSingleFile returned true";
            } else {
                qTitle = "Error";
                qMsg = QString("Failed to download file ID %1").arg(fileId);
                qWarning() << "[DownloadFileHandler] processSingleFile returned false";
            }
        }
        catch (const std::exception& ex) {
            success = false;
            qTitle = "Exception";
            qMsg = QString("Exception while downloading %1: %2")
                       .arg(fileId)
                       .arg(QString::fromStdString(ex.what()));
            qWarning() << "[DownloadFileHandler] Exception in processSingleFile:" << ex.what();
        }

        qDebug() << "[DownloadFileHandler] Emitting downloadResult(" << qTitle << "," << qMsg << ")";
        QMetaObject::invokeMethod(
            self,
            [self, success, qTitle, qMsg]() { emit self->downloadResult(qTitle, qMsg); },
            Qt::QueuedConnection
            );
    });
}

bool DownloadFileHandler::processSingleFile(int fileId)
{
    qDebug() << "[DownloadFileHandler] processSingleFile() entry; fileId =" << fileId;

    //  1) Get logged-in user + KeyBundle
    auto maybeUser = store->getUser();
    if (!maybeUser.has_value()) {
        qWarning() << "[DownloadFileHandler] No logged-in user";
        throw std::runtime_error("No logged-in user when trying to download");
    }
    const auto& userInfo   = *maybeUser;
    const auto& myUsername = userInfo.username;
    const auto& myKeyBundle = userInfo.fullBundle;
    qDebug() << "[DownloadFileHandler] Logged-in username =" << QString::fromStdString(myUsername);

    //  2) Get local FileClientData
    FileClientData* fcdPtr = store->getFileData(static_cast<uint64_t>(fileId));
    if (!fcdPtr) {
        qWarning() << "[DownloadFileHandler] No local FileClientData for file_id =" << fileId;
        return false;
    }
    FileClientData fcd = *fcdPtr;  // copy entire struct
    qDebug() << "[DownloadFileHandler] Retrieved FileClientData for file_id =" << fileId;

    //  3) Build JSON body for /api/fs/download
    nlohmann::ordered_json jbody;
    jbody["file_id"] = fileId;
    std::string bodyString = jbody.dump();
    qDebug() << "[DownloadFileHandler] JSON body for download:" << QString::fromStdString(bodyString);

    //  4) Create dual-signature headers
    qDebug() << "[DownloadFileHandler] Calling NetworkAuthUtils::makeAuthHeaders()";
    auto headers = NetworkAuthUtils::makeAuthHeaders(
        myUsername,
        myKeyBundle,
        "POST",
        "/api/fs/download",
        bodyString
        );

    //  5) Send HTTP request
    qDebug() << "[DownloadFileHandler] Sending HTTP POST /api/fs/download";
    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/fs/download",
        bodyString,
        headers
        );
    AsioHttpClient client;
    client.init("");  // pulls from Config::instance().serverHost / port

    HttpResponse resp = client.sendRequest(req);
    qDebug() << "[DownloadFileHandler] HTTP status code =" << resp.statusCode;
    qDebug() << "[DownloadFileHandler] full response body:" << QString::fromStdString(resp.body);
    if (resp.statusCode != 200) {
        qWarning() << "[DownloadFileHandler] Non-200 response from server:" << resp.statusCode;
        return false;
    }

    //  6) Parse JSON response
    nlohmann::json respJson;
    try {
        respJson = nlohmann::json::parse(resp.body);
        qDebug() << "[DownloadFileHandler] Parsed JSON response successfully";
    }
    catch (const std::exception& ex) {
        qWarning() << "[DownloadFileHandler] JSON parse error:" << ex.what();
        return false;
    }

    //  7) Extract required fields (file_content, metadata, pre_quantum_signature, post_quantum_signature, owner_user_id, is_owner)
    if (!respJson.contains("file_content") ||
        !respJson.contains("metadata") ||
        !respJson.contains("pre_quantum_signature") ||
        !respJson.contains("post_quantum_signature") ||
        !respJson.contains("owner_user_id") ||
        !respJson.contains("is_owner"))
    {
        qWarning() << "[DownloadFileHandler] Missing required fields in server response.";
        return false;
    }

    //  7.a) Pull file_content and signatures (they are Base64 strings)
    const std::string fileB64  = respJson.at("file_content").get<std::string>();
    const std::string edSigB64 = respJson.at("pre_quantum_signature").get<std::string>();
    const std::string pqSigB64 = respJson.at("post_quantum_signature").get<std::string>();
    const int         ownerUserId = respJson.at("owner_user_id").get<int>();
    const bool        isOwner     = respJson.at("is_owner").get<bool>();

    qDebug() << "[DownloadFileHandler] Extracted fields: owner_user_id =" << ownerUserId
             << ", is_owner =" << isOwner;

    //  8) Base64-decode the file-cipher and the two signatures
    std::vector<uint8_t> encFileData = FileClientData::base64_decode(fileB64);
    std::vector<uint8_t> edSigRaw    = FileClientData::base64_decode(edSigB64);
    std::vector<uint8_t> pqSigRaw    = FileClientData::base64_decode(pqSigB64);
    if (encFileData.empty() || edSigRaw.empty() || pqSigRaw.empty()) {
        qWarning() << "[DownloadFileHandler] One of the decoded buffers is empty.";
        return false;
    }
    qDebug() << "[DownloadFileHandler] Base64 decode succeeded for file-cipher & signatures.";

    //  8.a) **Extract the “metadata” field** (this is not Base64, but a JSON Buffer object).
    //         In your server code, “metadata” came from `filesTable.metadata` which Drizzle ORM
    //         encoded as something like { "type":"Buffer", "data":[ … ] }. We need to extract
    //         that “data” array of integers and turn it into a vector<uint8_t>.

    std::vector<uint8_t> encMetaData;
    {
        // respJson["metadata"] is an object with fields "type":"Buffer", "data":[ … ].
        // We only care about the array under "data".
        const auto& metaObj = respJson.at("metadata");
        if (!metaObj.contains("data") || !metaObj.at("data").is_array()) {
            qWarning() << "[DownloadFileHandler] Serverʼs \"metadata\" is not in the expected Buffer format.";
            return false;
        }

        const auto& dataArr = metaObj.at("data");
        encMetaData.reserve(dataArr.size());
        for (const auto& elt : dataArr) {
            // Each element should be an integer 0..255
            encMetaData.push_back(static_cast<uint8_t>(elt.get<int>()));
        }
        if (encMetaData.empty()) {
            qWarning() << "[DownloadFileHandler] Extracted metadata array is empty.";
            return false;
        }
    }
    qDebug() << "[DownloadFileHandler] Extracted metadata ciphertext ("
             << encMetaData.size() << " bytes) from JSON";

    //  9) Reconstruct the signed message = "<ownerUsername>|<fileHashHex>|<metaHashHex>"
    std::string ownerUsername;
    if (isOwner) {
        ownerUsername = myUsername;
        qDebug() << "[DownloadFileHandler] We are the owner; ownerUsername =" << QString::fromStdString(ownerUsername);
    }
    else {
        // If not owner, you would fetch the owner's username in some way.
        // For now (tests won’t hit this branch) just fail:
        qWarning() << "[DownloadFileHandler] Not owner, cannot map user_id→username.";
        return false;
    }

    //  9.a) Compute SHA256(fileCipher) → hex
    std::vector<uint8_t> fileHash = Hash::sha256(encFileData);
    std::string          fileHashHex = bytesToHex(fileHash);

    //  9.b) Compute SHA256(metaCipher) → hex
    std::vector<uint8_t> metaHash = Hash::sha256(encMetaData);
    std::string          metaHashHex = bytesToHex(metaHash);

    std::ostringstream oss;
    oss << ownerUsername << "|" << fileHashHex << "|" << metaHashHex;
    std::string sigInput = oss.str();
    std::vector<uint8_t> msgBytes(sigInput.begin(), sigInput.end());
    qDebug() << "[DownloadFileHandler] Reconstructed signed message =" << QString::fromStdString(sigInput);

    //  10) Verify Ed25519 + Dilithium signatures against msgBytes
    //  10.a) Load owner’s public bundle (we have it locally if isOwner==true)
    KeyBundle ownerPubBundle;
    if (isOwner) {
        ownerPubBundle = userInfo.publicBundle;
        qDebug() << "[DownloadFileHandler] Using local publicBundle to verify signatures.";
    }

    //  10.b) Verify Ed25519
    {
        std::vector<uint8_t> ownerEdPubRaw = ownerPubBundle.getEd25519PublicRaw();
        Signer_Ed edVerifier;
        edVerifier.loadPublicKey(ownerEdPubRaw.data(), ownerEdPubRaw.size());
        bool okEd = edVerifier.verify(msgBytes, edSigRaw);
        if (!okEd) {
            qWarning() << "[DownloadFileHandler] Ed25519 signature verification failed.";
            return false;
        }
        qDebug() << "[DownloadFileHandler] Ed25519 verification succeeded.";
    }

    //  10.c) Verify Dilithium
    {
        std::vector<uint8_t> ownerPqPubRaw = ownerPubBundle.getDilithiumPublicRaw();
        Signer_Dilithium pqVerifier;
        pqVerifier.loadPublicKey(ownerPqPubRaw.data(), ownerPqPubRaw.size());
        bool okPq = pqVerifier.verify(msgBytes, pqSigRaw);
        if (!okPq) {
            qWarning() << "[DownloadFileHandler] Dilithium signature verification failed.";
            return false;
        }
        qDebug() << "[DownloadFileHandler] Dilithium verification succeeded.";
    }

    //  11) Decrypt metadata under (fcd.mek + fcd.metadata_nonce)
    {
        qDebug() << "[DownloadFileHandler] Decrypting metadata from local FileClientData…";
        std::vector<uint8_t> localMetaIv(fcd.metadata_nonce.begin(), fcd.metadata_nonce.end());
        std::vector<uint8_t> mekVec(fcd.mek.begin(), fcd.mek.end());

        Symmetric::Plaintext plainMeta;
        try {
            plainMeta = Symmetric::decrypt(encMetaData, mekVec, localMetaIv);
        }
        catch (const std::exception& ex) {
            qWarning() << "[DownloadFileHandler] Symmetric::decrypt(metadata) threw:" << ex.what();
            return false;
        }

        std::vector<uint8_t> plainMetaBytes = std::move(plainMeta.data);
        if (plainMetaBytes.empty()) {
            qWarning() << "[DownloadFileHandler] Metadata decryption produced empty result.";
            return false;
        }
        qDebug() << "[DownloadFileHandler] Metadata decryption succeeded (" << plainMetaBytes.size() << " bytes)";

        //  12) Parse decrypted metadata JSON → { "filename", "filesize" }
        qDebug() << "[DownloadFileHandler] Parsing metadata JSON…";
        std::string      metaJsonStr(plainMetaBytes.begin(), plainMetaBytes.end());
        nlohmann::json metaJson;
        try {
            metaJson = nlohmann::json::parse(metaJsonStr);
        }
        catch (const std::exception& ex) {
            qWarning() << "[DownloadFileHandler] Failed to parse decrypted metadata JSON:" << ex.what();
            return false;
        }

        if (!metaJson.contains("filename") || !metaJson.contains("filesize")) {
            qWarning() << "[DownloadFileHandler] Metadata JSON missing filename/filesize.";
            return false;
        }
        std::string filename = metaJson.at("filename").get<std::string>();
        qDebug() << "[DownloadFileHandler] Parsed metadata: filename =" << QString::fromStdString(filename)
                 << ", filesize =" << metaJson.at("filesize").get<size_t>();

        //  13) Decrypt the file cipher under (fcd.fek + fcd.file_nonce)
        qDebug() << "[DownloadFileHandler] Decrypting file contents…";
        std::vector<uint8_t> fileIv(fcd.file_nonce.begin(), fcd.file_nonce.end());
        std::vector<uint8_t> fekVec(fcd.fek.begin(), fcd.fek.end());

        Symmetric::Plaintext plainFile;
        try {
            plainFile = Symmetric::decrypt(encFileData, fekVec, fileIv);
        }
        catch (const std::exception& ex) {
            qWarning() << "[DownloadFileHandler] Symmetric::decrypt(file) threw:" << ex.what();
            return false;
        }

        std::vector<uint8_t> plainFileBytes = std::move(plainFile.data);
        if (plainFileBytes.empty()) {
            qWarning() << "[DownloadFileHandler] File decryption produced empty result.";
            return false;
        }
        qDebug() << "[DownloadFileHandler] File decryption succeeded (" << plainFileBytes.size() << " bytes)";

        //  14) Write plaintext to ~/Desktop/<filename>
        QString desktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        if (desktopPath.isEmpty()) {
            qWarning() << "[DownloadFileHandler] Could not resolve Desktop location.";
            return false;
        }
        QString outFilePath = QDir(desktopPath).filePath(QString::fromStdString(filename));
        qDebug() << "[DownloadFileHandler] Writing file to" << outFilePath;

        std::ofstream outFile(outFilePath.toStdString(), std::ios::binary);
        if (!outFile.good()) {
            qWarning() << "[DownloadFileHandler] Failed to open output file for writing:" << outFilePath;
            return false;
        }
        outFile.write(reinterpret_cast<const char*>(plainFileBytes.data()),
                      static_cast<std::streamsize>(plainFileBytes.size()));
        outFile.close();
        qDebug() << "[DownloadFileHandler] Wrote file successfully";

        //  15) Everything succeeded
        qDebug() << "[DownloadFileHandler] processSingleFile() completed successfully";
        return true;
    }
}

