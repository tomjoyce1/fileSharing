#include "FileDownloadHandler.h"
#include "../utils/networking/asiosslclient.h"
#include "../config.h"
#include <QMetaObject>
#include <QDebug>
#include <QFile>


namespace {
static std::string toHex(const std::vector<uint8_t> &data) {
    static const char *lut = "0123456789abcdef";
    std::string out; out.reserve(data.size()*2);
    for (uint8_t b : data) { out.push_back(lut[b>>4]); out.push_back(lut[b&0x0F]); }
    return out;
}
}

FileDownloadHandler::FileDownloadHandler(ClientStore *s, QObject *parent): QObject(parent), store(s) {}

// Saves to a new file at a specified path
bool FileDownloadHandler::saveToFile(const QString &path,
                                     const QByteArray &data)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(data) == data.size();
}


bool FileDownloadHandler::saveToDownloads(const QString &fileName,
                                          const QByteArray &data)
{
    // Platforms native download dir
    QString downloadsDir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (downloadsDir.isEmpty()) {
        downloadsDir = QDir::homePath() + "/Downloads";
    }

    QDir().mkpath(downloadsDir); // ensure it exists
    QString fullPath = QDir(downloadsDir).filePath(fileName);

    if (!saveToFile(fullPath, data)) {
        qWarning() << "[FileDownload] saving failed →" << fullPath;
        return false;
    }
    qInfo() << "[FileDownload] saved ↓" << fullPath;
    return true;
}

void FileDownloadHandler::downloadFile(qulonglong fileId)
{
    // Process that file
    HandlerUtils::runAsync([this, fileId]() { processSingleFile(fileId); });
}



void FileDownloadHandler::processSingleFile(qulonglong fileId)
{

    // look up FileClientData (owner-only path)
    FileClientData *fcd = store->getFileData(fileId);
    if (!fcd) {
        // TODO: implement for shared file
        emit downloadResult("Error",
                            QString("File %1 not in local store (shared download not implemented)")
                                .arg(fileId));
        return;
    }

    // Construct json body
    nlohmann::json jBody; jBody["file_id"] = static_cast<uint64_t>(fileId);
    std::string bodyStr = jBody.dump();

    // Construct auth headers
    auto maybeUser = store->getUser();
    if (!maybeUser.has_value()) throw std::runtime_error("No logged-in user");
    const auto &userInfo  = *maybeUser;
    const auto &username  = userInfo.username;
    const auto &privBundle= userInfo.fullBundle;

    auto headers = NetworkAuthUtils::makeAuthHeaders(
        username, privBundle,
        "POST", "/api/fs/download", bodyStr);

    // HTTP POST
    HttpRequest req(HttpRequest::Method::POST, "/api/fs/download", bodyStr, headers);

    AsioSslClient  client;
    HttpResponse resp = client.sendRequest(req);

    if (resp.statusCode != 200) {
        emit downloadResult("Error",
                            QString("Server returned %1 for file %2").arg(resp.statusCode).arg(fileId));
        return;
    }

    // Parse the JSON response
    nlohmann::json jResp = nlohmann::json::parse(resp.body);
    bool isOwner = jResp.at("is_owner").get<bool>();
    if (!isOwner) {
        // TODO: Implement this later
        emit downloadResult("Info",
                            QString("File %1 is shared; client lacks sharing support").arg(fileId));
        return;
    }

    std::string fileB64 = jResp.at("file_content").get<std::string>();
    // metadata can arrive as either a base-64 string or a Buffer object
    std::string metaB64;
    {
        const auto &m = jResp.at("metadata");

        if (m.is_string()) {
            metaB64 = m.get<std::string>();
        }
        else if (m.is_object()
                 && m.value("type", "")  == "Buffer"
                 && m.contains("data")   && m["data"].is_array())
        {
            // convert `{ type:"Buffer", data:[ … ] }` → base64
            const auto &arr = m["data"];
            std::vector<uint8_t> bytes(arr.size());
            for (size_t i = 0; i < arr.size(); ++i)
                bytes[i] = static_cast<uint8_t>(arr[i].get<int>());

            metaB64 = FileClientData::base64_encode(bytes.data(), bytes.size());
        }
        else {
            throw std::runtime_error("Unexpected JSON shape for metadata");
        }
    }
    std::string edSigB64 = jResp.at("pre_quantum_signature").get<std::string>();
    std::string pqSigB64 = jResp.at("post_quantum_signature").get<std::string>();


    // Verify signatures
    std::string verifyErr;
    if (!verifySignatures(username, fileB64, metaB64,
                          edSigB64, pqSigB64,
                          userInfo.publicBundle, verifyErr)) {
        emit downloadResult("Error",
                            QString("Signature verification failed: %1").arg(
                                QString::fromStdString(verifyErr)));
        return;
    }

    // Decrypt
    std::vector<uint8_t> fileCipher = FileClientData::base64_decode(fileB64);
    std::vector<uint8_t> metaCipher = FileClientData::base64_decode(metaB64);

    Symmetric::Plaintext plainFile = Symmetric::decrypt(
        fileCipher,
        std::vector<uint8_t>(fcd->fek.begin(), fcd->fek.end()),
        std::vector<uint8_t>(fcd->file_nonce.begin(), fcd->file_nonce.end())
        );

    Symmetric::Plaintext plainMeta = Symmetric::decrypt(
        metaCipher,
        std::vector<uint8_t>(fcd->mek.begin(), fcd->mek.end()),
        std::vector<uint8_t>(fcd->metadata_nonce.begin(), fcd->metadata_nonce.end())
        );

    // Get filename from metadata
    std::string fileName = fcd->filename;
    try {
        nlohmann::json jMeta = nlohmann::json::parse(
            std::string(reinterpret_cast<char*>(plainMeta.data.data()),
                        plainMeta.data.size()));
        fileName = jMeta.value("filename", fileName);
    } catch (...) {
        qDebug().nospace() << "Filename not found in metadata, defaulting to the filename stored in file client data";
    }

    QByteArray ba(reinterpret_cast<const char*>(plainFile.data.data()),
                  static_cast<int>(plainFile.data.size()));

    // Save the byte array to downloads
    if (!saveToDownloads(QString::fromStdString(fileName), ba)) {
        emit downloadResult("Error", "Could not write into Downloads folder");
        return;
    }

    emit downloadResult("Success",
                        QString("Saved to Downloads (%1 bytes)").arg(ba.size()));
    emit fileReady(fileId, QString::fromStdString(fileName), ba);
}

bool FileDownloadHandler::verifySignatures(const std::string &username,
                                           const std::string &fileB64,
                                           const std::string &metaB64,
                                           const std::string &edSigB64,
                                           const std::string &pqSigB64,
                                           const KeyBundle   &pubBundle,
                                           std::string       &outError)
{
    // Decode ciphertexts
    std::vector<uint8_t> fileCipher = FileClientData::base64_decode(fileB64);
    std::vector<uint8_t> metaCipher = FileClientData::base64_decode(metaB64);

    // Rebuild canonical string  username|sha256(file)|sha256(meta)
    std::string fileHashHex = toHex(Hash::sha256(fileCipher));
    std::string metaHashHex = toHex(Hash::sha256(metaCipher));
    std::ostringstream oss;
    oss << username << '|' << fileHashHex << '|' << metaHashHex;
    std::string canonical = oss.str();
    std::vector<uint8_t> msgBytes(canonical.begin(), canonical.end());

    // Ed25519 verification
    std::vector<uint8_t> edSig   = FileClientData::base64_decode(edSigB64);
    const auto&          edPub   = pubBundle.getEd25519Pub();   // 32-byte raw

    Signer_Ed verifierEd;
    verifierEd.loadPublicKey(edPub.data(), edPub.size());

    if (!verifierEd.verify(msgBytes, edSig)) {
        outError = "Ed25519 failed";
        return false;
    }

    // Dilithium verification
    std::vector<uint8_t> pqSig = FileClientData::base64_decode(pqSigB64);
    const auto&          pqPub = pubBundle.getDilithiumPub();   // 2 592 B

    Signer_Dilithium verifierPQ;
    verifierPQ.loadPublicKey(pqPub.data(), pqPub.size());

    if (!verifierPQ.verify(msgBytes, pqSig)) {
        outError = "Dilithium failed";
        return false;
    }

    return true;   // both signatures OK
}

