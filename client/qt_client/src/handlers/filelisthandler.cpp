// FileListHandler.cpp

#include "FileListHandler.h"
#include "../utils/networking/AsioHttpClient.h"       // Your synchronous HTTP/1.1 client wrapper
#include "../utils/NetworkAuthUtils.h"     // For makeAuthHeaders(...)
#include <QDebug>
#include <sstream>
#include <iomanip>
#include <map>

// For convenience
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
    m_privBundle = info.fullBundle;  // Contains x25519Priv, ed25519Priv, pqPriv, etc.
}

void FileListHandler::listAllFiles(int page) {
    fetchPage(page, /*onlyOwned=*/false, /*onlyShared=*/false);
}

void FileListHandler::listOwnedFiles(int page) {
    fetchPage(page, /*onlyOwned=*/true,  /*onlyShared=*/false);
}

void FileListHandler::listSharedFiles(int page) {
    fetchPage(page, /*onlyOwned=*/false, /*onlyShared=*/true);
}

void FileListHandler::fetchPage(int page, bool onlyOwned, bool onlyShared) {
    // 1) Build POST body
    std::string bodyStr = buildPostBody(page);

    // 2) Create signed headers
    auto headersMap = NetworkAuthUtils::makeAuthHeaders(
        m_username.toStdString(),
        m_privBundle,
        "POST",
        "/api/fs/list",
        bodyStr
        );
    // Ensure "Content-Type: application/json"
    headersMap["Content-Type"] = "application/json";

    // 3) Send the HTTP request
    QString httpError;
    auto maybeJson = sendListRequest(bodyStr, headersMap, httpError);
    if (!maybeJson.has_value()) {
        emit errorOccurred(httpError);
        return;
    }
    json fullResp = *maybeJson;

    // 4) Validate that “fileData” exists and is an array
    if (!fullResp.contains("fileData") || !fullResp["fileData"].is_array()) {
        QString errMsg = "Malformed response: missing fileData[]";
        qWarning() << "[FileList]" << errMsg;
        emit errorOccurred(errMsg);
        return;
    }

    // 5) Process the array into a QVariantList
    auto decryptedList = processFileArray(fullResp["fileData"], onlyOwned, onlyShared);

    // 6) Emit results (even if empty)
    emit filesLoaded(decryptedList);
}

std::string FileListHandler::buildPostBody(int page) const {
    json postBody = { { "page", page } };
    return postBody.dump();
}


std::optional<json> FileListHandler::sendListRequest(
    const std::string& bodyStr,
    const std::map<std::string, std::string>& headers,
    QString& outError
    ) {
    AsioHttpClient client;
    client.init("");  // rely on default host/port from config

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
    // 1) Parse & decrypt into our intermediate struct
    auto maybeDec = parseAndDecryptSingle(singleFileJson);
    if (!maybeDec.has_value()) {
        return std::nullopt;
    }
    const DecryptedFile& df = *maybeDec;

    // 2) Build a QVariantMap with exactly the keys QML expects
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


//------------------------------------------------------------------------------
// parseAndDecryptSingle(...) and unwrapKeysFromJson(...) are extracted mostly
// verbatim from your existing implementation, with only minimal re-formatting
// to fit into this new structure. No logic was changed.
//------------------------------------------------------------------------------

std::optional<DecryptedFile> FileListHandler::parseAndDecryptSingle(
    const json& singleFileJson
    ) {
    DecryptedFile result;
    result.file_id   = singleFileJson.at("file_id").get<uint64_t>();
    result.is_owner  = singleFileJson.at("is_owner").get<bool>();
    result.is_shared = singleFileJson.contains("shared_access");
    result.shared_from.clear();

    // 1) Retrieve local FileClientData for this file_id
    FileClientData* fcdPtr = m_store->getFileData(result.file_id);
    if (fcdPtr == nullptr) {
        qWarning() << "[FileList] No local FileClientData for file_id="
                   << result.file_id;
        return std::nullopt;
    }
    FileClientData fcd = *fcdPtr;  // copy the struct

    // 2) Determine which MEK and metadata_nonce to use
    std::vector<uint8_t> finalMEK(32);
    std::vector<uint8_t> iv_metadata(16);

    if (result.is_owner) {
        // If we own the file, we already stored MEK + metadata_nonce in FileClientData
        finalMEK    = std::vector<uint8_t>(fcd.mek.begin(), fcd.mek.end());
        iv_metadata = std::vector<uint8_t>(fcd.metadata_nonce.begin(),
                                           fcd.metadata_nonce.end());
    }
    else {
        // If it’s shared to us, unwrap FEK/MEK from the shared_access block
        auto [rawFEK, rawMEK] = unwrapKeysFromJson(singleFileJson, m_privBundle);
        Q_UNUSED(rawFEK); // for listing metadata, we only need MEK right now

        finalMEK = rawMEK;

        // The server’s JSON has a base64‐encoded metadata_nonce under shared_access
        std::string b64_metaNonce =
            singleFileJson["shared_access"]["metadata_nonce"].get<std::string>();

        std::vector<uint8_t> decodedMetaNonce =
            FileClientData::base64_decode(b64_metaNonce);
        if (decodedMetaNonce.size() != FileClientData::PUBLIC_NONCE_LEN) {
            qWarning() << "[FileList] Invalid metadata_nonce length in shared_access";
            return std::nullopt;
        }
        iv_metadata = decodedMetaNonce;

        // Optionally record who shared it (if the server returned “shared_by”)
        if (singleFileJson["shared_access"].contains("shared_by")) {
            result.shared_from = QString::fromStdString(
                singleFileJson["shared_access"]["shared_by"].get<std::string>()
                );
        }
    }

    // 3) Base64‐decode “metadata” ciphertext, then AES-CTR‐decrypt with finalMEK + iv_metadata
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

    // 4) Parse the plaintext JSON of metadata
    std::string metaJsonStr(reinterpret_cast<char*>(ptxt.data.data()),
                            ptxt.data.size());

    json metaJson;
    try {
        metaJson = json::parse(metaJsonStr);
    }
    catch (const std::exception& ex) {
        qWarning() << "[FileList] Invalid metadata JSON for file_id="
                   << result.file_id << ":" << ex.what();
        return std::nullopt;
    }

    qDebug() << "[FileList] Decrypted metadata for file_id="
             << result.file_id
             << ":" << QString::fromStdString(metaJson.dump());

    // Fill out filename + size
    result.filename   = QString::fromStdString(
        metaJson.at("filename").get<std::string>()
        );
    result.size_bytes = metaJson.at("filesize").get<uint64_t>();

    // 5) timestamp: prefer metadata, else fallback to server’s field
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
FileListHandler::unwrapKeysFromJson(
    const json& singleFileJson,
    const KeyBundle&      privBundle
    ) {
    // 1) Base64‐decode the server’s ephemeral_public_key (32‐byte X25519 public)
    std::string b64_ephPub =
        singleFileJson["shared_access"]["ephemeral_public_key"].get<std::string>();
    std::vector<uint8_t> ephPub = FileClientData::base64_decode(b64_ephPub);
    if (ephPub.size() != crypto_scalarmult_BYTES) {
        throw std::runtime_error("unwrapKeysFromJson: invalid ephemeral_public_key length");
    }

    // 2) Base64‐decode our own x25519 private key (32 bytes)
    std::string x25519PrivB64 = privBundle.getX25519PrivateKeyBase64();
    std::vector<uint8_t> x25519Priv = FileClientData::base64_decode(x25519PrivB64);
    if (x25519Priv.size() != crypto_scalarmult_SCALARBYTES) {
        throw std::runtime_error("unwrapKeysFromJson: invalid x25519 private key length");
    }

    // 3) Perform ECDH: sharedSecret = X25519(x25519Priv, ephPub)
    std::vector<uint8_t> sharedSecret(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(
            sharedSecret.data(),
            x25519Priv.data(),
            ephPub.data()
            ) != 0) {
        throw std::runtime_error("unwrapKeysFromJson: X25519 ECDH failed");
    }

    // 4a) Decrypt the FEK (32 bytes) under sharedSecret (AES-256-CTR)
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

    // 4b) Decrypt the MEK (32 bytes) under sharedSecret (AES-256-CTR)
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

    // 5) Return <FEK, MEK> as two raw 32-byte vectors
    std::vector<uint8_t> rawFEK(fekPtxt.data.begin(), fekPtxt.data.end());
    std::vector<uint8_t> rawMEK(mekPtxt.data.begin(), mekPtxt.data.end());
    return { rawFEK, rawMEK };
}
