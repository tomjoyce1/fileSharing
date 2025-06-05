#include "FileListHandler.h"
#include "../utils/networking/asiosslclient.h"
#include "../config.h"
#include "../utils/NetworkAuthUtils.h"
#include "../utils/handlerutils.h"
#include <QDebug>
#include <map>

static std::string first8(const std::vector<uint8_t>& v)
{
    char buf[17];
    for (int i = 0; i < 8; ++i) sprintf(buf + 2*i, "%02x", v[i]);
    buf[16] = 0;
    return buf;
}

using json = nlohmann::json;

FileListHandler::FileListHandler(ClientStore* store, QObject* parent)
    : QObject(parent), m_store(store)
{
    // Immediately fetch the logged-in user’s info from ClientStore
    auto userOpt = m_store->getUser();
    if (!userOpt.has_value()) {
        qWarning() << "[FileListHandler] No user logged in; cannot list files.";
        emit errorOccurred("No user logged in");
        return;
    }

    // Extract username and private KeyBundle
    const auto& info = *userOpt;
    m_username   = QString::fromStdString(info.username);
    m_privBundle = info.fullBundle;
}

void FileListHandler::listAllFiles(int page) {
    fetchPage(page, false, false);
}

void FileListHandler::listOwnedFiles(int page) {
    fetchPage(page, true, false);
}

void FileListHandler::listSharedFiles(int page) {
    fetchPage(page, false, true);
}

void FileListHandler::fetchPage(int page, bool onlyOwned, bool onlyShared) {
    // Build POST body
    std::string bodyStr = buildPostBody(page);

    // Create Canonical String
    auto headersMap = NetworkAuthUtils::makeAuthHeaders(
        m_username.toStdString(),
        m_privBundle,
        "POST",
        "/api/fs/list",
        bodyStr
        );
    headersMap["Content-Type"] = "application/json";

    // Send the HTTP request
    QString httpError;
    auto maybeJson = sendListRequest(bodyStr, headersMap, httpError);
    if (!maybeJson.has_value()) {
        emit errorOccurred(httpError);
        return;
    }
    json fullResp = *maybeJson;

    // Validate that “fileData” exists and is an array
    if (!fullResp.contains("fileData") || !fullResp["fileData"].is_array()) {
        QString errMsg = "Malformed response: missing fileData[]";
        qWarning() << "[FileList]" << errMsg;
        emit errorOccurred(errMsg);
        return;
    }

    // Process the array into a QVariantList
    auto decryptedList = processFileArray(fullResp["fileData"], onlyOwned, onlyShared);

    // Emit results
    emit filesLoaded(decryptedList);
}

std::string FileListHandler::buildPostBody(int page) const {
    json postBody = { { "page", page } };
    return postBody.dump();
}

void FileListHandler::deleteFile(qulonglong fileId)
{
    HandlerUtils::runAsync([this, fileId]() {
        auto maybeUser = m_store->getUser();
        if (!maybeUser.has_value()) {
            emit errorOccurred("Not logged-in");
            return;
        }
        const auto& user   = *maybeUser;
        const auto& uname  = user.username;
        const auto& bundle = user.fullBundle;

        // build Json body
        nlohmann::json jBody;  jBody["file_id"] = static_cast<uint64_t>(fileId);
        std::string bodyStr = jBody.dump();

        auto headers = NetworkAuthUtils::makeAuthHeaders(
            uname, bundle,
            "POST", "/api/fs/delete", bodyStr);

        HttpRequest        req(HttpRequest::Method::POST, "/api/fs/delete", bodyStr, headers);
        AsioSslClient      cli;
        HttpResponse       resp = cli.sendRequest(req);

        if (resp.statusCode != 200) {
            emit deleteResult("Error",  "Delete Failed");
            emit errorOccurred("Delete Failed");
            return;
        }

        //success → drop from ClientStore
        m_store->removeFileData(fileId);

        // Refresh list on the UI thread               */
        QMetaObject::invokeMethod(this, [this](){ listAllFiles(/*page=*/1); }, Qt::QueuedConnection);

        emit deleteResult("Success", "File deleted successfully");
    });
}


std::optional<json> FileListHandler::sendListRequest(
    const std::string& bodyStr,
    const std::map<std::string, std::string>& headers,
    QString& outError
    ) {
    AsioSslClient client;

    // Build and send the request
    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/fs/list",
        bodyStr,
        headers
        );
    HttpResponse resp = client.sendRequest(req);

    if (resp.statusCode != 200) {
        outError = QString("ListFiles HTTP %1: %2")
                       .arg(resp.statusCode)
                       .arg(QString::fromStdString(resp.body));
        qWarning() << "[FileList]" << outError;
        return std::nullopt;
    }

    // Parse response body as JSON
    try {
        return json::parse(resp.body);
    }
    catch (const std::exception& ex) {
        outError = QString("Failed to parse JSON from /api/fs/list: %1")
                       .arg(ex.what());
        qWarning() << "[FileList]" << outError;
        return std::nullopt;
    }
}

QVariantList FileListHandler::processFileArray(
    const json& fileArray,
    bool onlyOwned,
    bool onlyShared
    ) {
    QVariantList outList;
    outList.reserve(fileArray.size());

    for (const auto& jFile : fileArray) {
        bool isOwner = jFile.at("is_owner").get<bool>();
        if (onlyOwned  && !isOwner)  continue;
        if (onlyShared && isOwner)   continue;

        // Decrypt & turn into QVariantMap
        auto maybeMap = decryptSingleToVariant(jFile);
        if (!maybeMap.has_value()) {
            qWarning() << "[FileList] Skipping file_id="
                       << static_cast<qulonglong>(jFile.value("file_id", 0))
                       << "due to decrypt error.";
            continue;
        }
        outList.push_back(*maybeMap);
    }

    return outList;
}

std::optional<QVariantMap> FileListHandler::decryptSingleToVariant(
    const json& singleFileJson
    ) {
    // Parse & decrypt into our intermediate struct
    auto maybeDec = parseAndDecryptSingle(singleFileJson);
    if (!maybeDec.has_value()) {
        return std::nullopt;
    }
    const DecryptedFile& df = *maybeDec;

    // Build a QVariantMap with exactly the keys QML expects
    QVariantMap singleMap;
    singleMap["file_id"]     = (qulonglong) df.file_id;
    singleMap["filename"]    = df.filename;
    singleMap["size"]        = (qulonglong) df.size_bytes;
    singleMap["modified"]    = df.upload_timestamp;
    singleMap["is_owner"]    = df.is_owner;
    singleMap["is_shared"]   = df.is_shared;
    singleMap["shared_from"] = df.shared_from;

    return singleMap;
}

std::optional<DecryptedFile> FileListHandler::parseAndDecryptSingle(
    const json& singleFileJson
    ) {
    DecryptedFile result;
    result.file_id   = singleFileJson.at("file_id").get<uint64_t>();
    result.is_owner  = singleFileJson.at("is_owner").get<bool>();
    result.is_shared = singleFileJson.contains("shared_access");
    result.shared_from.clear();

    // Retrieve local FileClientData for this file_id
    FileClientData* fcd = m_store->getFileData(result.file_id);

    std::vector<uint8_t> finalMEK(32);
    std::vector<uint8_t> iv_metadata(16);

    if (result.is_owner)
    {
        /* we really need the local copy for owned files */
        FileClientData* fcdPtr = m_store->getFileData(result.file_id);
        if (!fcdPtr) {
            qWarning() << "[FileList]    owner but no local keys for file_id="
                       << result.file_id;
            return std::nullopt;
        }

        finalMEK    = { fcdPtr->mek.begin(), fcdPtr->mek.end() };
        iv_metadata = { fcdPtr->metadata_nonce.begin(),
                       fcdPtr->metadata_nonce.end() };
    }
    else                // ───── shared file path ─────
    {
        try {
            // ❶  unwrap FEK / MEK with the shared-secret
            auto [rawFEK, rawMEK] = unwrapKeysFromJson(singleFileJson,
                                                       m_privBundle);

            // ❷  IV that the sharer sent for the metadata blob
            std::string ivB64 = singleFileJson["shared_access"]["metadata_nonce"]
                                    .get<std::string>();
            iv_metadata = FileClientData::base64_decode(ivB64);
            if (iv_metadata.size() != FileClientData::PUBLIC_NONCE_LEN)
                           throw std::runtime_error("metadata_nonce wrong length");

                        finalMEK = std::move(rawMEK);

                        /* optional – cache for later downloads */
                       FileClientData cache(result.file_id);
            cache.file_id = result.file_id;              // ctor that zeros
            std::copy(rawMEK.begin(),  rawMEK.end(),  cache.mek.begin());
            std::copy(rawFEK.begin(),  rawFEK.end(),  cache.fek.begin());
            std::copy(iv_metadata.begin(), iv_metadata.end(),
                      cache.metadata_nonce.begin());
            m_store->upsertFileData(cache);

            result.shared_from =
                QString::fromStdString(
                    singleFileJson["owner_username"].get<std::string>());
        }
        catch (const std::exception& ex) {
            qWarning() << "[FileList] shared-file unwrap failed for file_id="
                       << result.file_id << ":" << ex.what();
            return std::nullopt;
        }
    }

    // Base64‐decode “metadata” ciphertext, then AES-CTR‐decrypt with finalMEK + iv_metadata
    std::string metaB64 = singleFileJson.at("metadata").get<std::string>();
    std::vector<uint8_t> metaCipherBytes = FileClientData::base64_decode(metaB64);

    Symmetric::Ciphertext ctext;
    ctext.data = metaCipherBytes;
    ctext.iv   = iv_metadata;

    Symmetric::Plaintext ptxt;
    try {
        ptxt = Symmetric::decrypt(ctext.data, finalMEK, ctext.iv);
    }
    catch (const std::exception& ex) {
        qWarning() << "[FileList] Failed to decrypt metadata for file_id="
                   << result.file_id << ":" << ex.what();
        return std::nullopt;
    }

    // Parse the plaintext JSON of metadata
    std::string metaJsonStr(reinterpret_cast<char*>(ptxt.data.data()), ptxt.data.size());

    json metaJson;
    try {
        metaJson = json::parse(metaJsonStr);
    }
    catch (const std::exception& ex) {
        qWarning() << "[FileList] Invalid metadata JSON for file_id="
                   << result.file_id << ":" << ex.what();
        return std::nullopt;
    }

    // Fill out filename + size
    if (!metaJson.contains("filename") || !metaJson.contains("filesize")) {
        qWarning() << "[FileList] metadata for file_id=" << result.file_id
                   << "is missing filename / filesize – skipping.";
        return std::nullopt;            // skip this entry instead of aborting
    }


    result.filename   = QString::fromStdString(
        metaJson.at("filename").get<std::string>()
        );
    result.size_bytes = metaJson.at("filesize").get<uint64_t>();

    // timestamp: prefer metadata, else fallback to server’s field
    if (metaJson.contains("upload_timestamp")) {
        std::string ts = metaJson["upload_timestamp"].get<std::string>();
        QDateTime dt = QDateTime::fromString(QString::fromStdString(ts), Qt::ISODate);
        result.upload_timestamp = dt.isValid() ? dt : QDateTime();
    }
    else if (singleFileJson.contains("upload_timestamp")) {
        std::string srvTs = singleFileJson["upload_timestamp"].get<std::string>();
        QDateTime dt = QDateTime::fromString(QString::fromStdString(srvTs), Qt::ISODate);
        result.upload_timestamp = dt.isValid() ? dt : QDateTime();
    }
    else {
        result.upload_timestamp = QDateTime();
    }

    return result;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
FileListHandler::unwrapKeysFromJson(const json& singleFileJson, const KeyBundle& privBundle) {

    // Base64‐decode the server’s ephemeral_public_key (32‐byte X25519 public)
    std::string b64_ephPub = singleFileJson["shared_access"]["ephemeral_public_key"].get<std::string>();
    std::vector<uint8_t> ephPub = FileClientData::base64_decode(b64_ephPub);
    if (ephPub.size() != crypto_scalarmult_BYTES) {
        throw std::runtime_error("unwrapKeysFromJson: invalid ephemeral_public_key length");
    }

    // Base64‐decode our own x25519 private key (32 bytes)
    std::string x25519PrivB64 = privBundle.getX25519PrivateKeyBase64();
    std::vector<uint8_t> x25519Priv = FileClientData::base64_decode(x25519PrivB64);
    if (x25519Priv.size() != crypto_scalarmult_SCALARBYTES) {
        throw std::runtime_error("unwrapKeysFromJson: invalid x25519 private key length");
    }

    // Perform ECDH: sharedSecret = X25519(x25519Priv, ephPub)
    std::vector<uint8_t> sharedSecret(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(sharedSecret.data(), x25519Priv.data(), ephPub.data()) != 0) {
        throw std::runtime_error("unwrapKeysFromJson: X25519 ECDH failed");
    }

    // Decrypt the FEK (32 bytes) under sharedSecret (AES-256-CTR)
    std::string b64_encFEK   = singleFileJson["shared_access"]["encrypted_fek"].get<std::string>();
    std::string b64_nonceFEK = singleFileJson["shared_access"]["encrypted_fek_nonce"].get<std::string>();
    std::vector<uint8_t> encFEK   = FileClientData::base64_decode(b64_encFEK);
    std::vector<uint8_t> nonceFEK = FileClientData::base64_decode(b64_nonceFEK);
    if (nonceFEK.size() != FileClientData::PUBLIC_NONCE_LEN) {
        throw std::runtime_error("unwrapKeysFromJson: invalid FEK nonce size");
    }

    Symmetric::Ciphertext fekCtxt;
    fekCtxt.data = encFEK;
    fekCtxt.iv   = nonceFEK;

    Symmetric::Plaintext fekPtxt;
    try {
        fekPtxt = Symmetric::decrypt(fekCtxt.data, sharedSecret, fekCtxt.iv);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("unwrapKeysFromJson: FEK decrypt failed: ") + ex.what());
    }
    if (fekPtxt.data.size() != FileClientData::PUBLIC_KEY_LEN) {
        throw std::runtime_error("unwrapKeysFromJson: FEK decrypted to wrong length");
    }

    // Decrypt the MEK (32 bytes) under sharedSecret (AES-256-CTR)
    std::string b64_encMEK   = singleFileJson["shared_access"]["encrypted_mek"].get<std::string>();
    std::string b64_nonceMEK = singleFileJson["shared_access"]["encrypted_mek_nonce"].get<std::string>();
    std::vector<uint8_t> encMEK   = FileClientData::base64_decode(b64_encMEK);
    std::vector<uint8_t> nonceMEK = FileClientData::base64_decode(b64_nonceMEK);
    if (nonceMEK.size() != FileClientData::PUBLIC_NONCE_LEN) {
        throw std::runtime_error("unwrapKeysFromJson: invalid MEK nonce size");
    }

    Symmetric::Ciphertext mekCtxt;
    mekCtxt.data = encMEK;
    mekCtxt.iv   = nonceMEK;

    Symmetric::Plaintext mekPtxt;
    try {
        mekPtxt = Symmetric::decrypt(mekCtxt.data, sharedSecret, mekCtxt.iv);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("unwrapKeysFromJson: MEK decrypt failed: ") + ex.what());
    }
    if (mekPtxt.data.size() != FileClientData::PUBLIC_KEY_LEN) {
        throw std::runtime_error("unwrapKeysFromJson: MEK decrypted to wrong length");
    }

    // Return <FEK, MEK> as two raw 32-byte vectors
    std::vector<uint8_t> rawFEK(fekPtxt.data.begin(), fekPtxt.data.end());
    std::vector<uint8_t> rawMEK(mekPtxt.data.begin(), mekPtxt.data.end());
    return { rawFEK, rawMEK };
}
