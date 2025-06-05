// FileDownloadHandler.cpp ----------------------------------------------------
#include "FileDownloadHandler.h"
#include <QMetaObject>
#include <QDebug>
#include <fstream>
#include <QFile>

// ───── NEW: simple logging macro ────────────────────────────────────────────
#ifndef FD_LOG
#  define FD_LOG(tag)  qDebug().nospace() << "[FileDownload][" << tag << "] "
#endif
// ────────────────────────────────────────────────────────────────────────────

namespace {
static std::string toHex(const std::vector<uint8_t> &data) {
    static const char *lut = "0123456789abcdef";
    std::string out; out.reserve(data.size()*2);
    for (uint8_t b : data) { out.push_back(lut[b>>4]); out.push_back(lut[b&0x0F]); }
    return out;
}
}

FileDownloadHandler::FileDownloadHandler(ClientStore *s, QObject *parent)
    : QObject(parent), store(s) {}

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
    // 1) platform-native Downloads dir (falls back to $HOME/Downloads)
    QString downloadsDir = QStandardPaths::writableLocation(
        QStandardPaths::DownloadLocation);
    if (downloadsDir.isEmpty())
        downloadsDir = QDir::homePath() + "/Downloads";

#ifdef Q_OS_ANDROID
    // Android: hard-code /sdcard/Download if standard path is empty
    if (downloadsDir.isEmpty())
        downloadsDir = "/sdcard/Download";
#endif

    QDir().mkpath(downloadsDir);                        // ensure it exists
    QString fullPath = QDir(downloadsDir).filePath(fileName);

    // 2) reuse existing saver
    if (!saveToFile(fullPath, data)) {
        qWarning() << "[FileDownload] saving failed →" << fullPath;
        return false;
    }
    qInfo() << "[FileDownload] saved ↓" << fullPath;
    return true;
}

void FileDownloadHandler::downloadFile(qulonglong fileId)
{
    FD_LOG("request") << "downloadFile(" << fileId << ")";
    HandlerUtils::runAsync([this, fileId]() { processSingleFile(fileId); });
}

// ─── helper ─────────────────────────────────────────────────────────────
static std::string fieldToBase64(const nlohmann::json& jField,
                                 const char*            tagForLog)
{
    if (jField.is_string()) {
        FD_LOG("json") << tagForLog << " is already base64 string";
        return jField.get<std::string>();
    }
    if (jField.is_object()
        && jField.contains("type") && jField["type"] == "Buffer"
        && jField.contains("data") && jField["data"].is_array())
    {
        const auto& arr = jField["data"];
        std::vector<uint8_t> bytes;
        bytes.reserve(arr.size());
        for (const auto& v : arr) bytes.push_back(static_cast<uint8_t>(v.get<int>()));

        std::string b64 = FileClientData::base64_encode(bytes.data(), bytes.size());
        FD_LOG("json") << tagForLog << " converted Buffer → base64 (bytes="
                       << bytes.size() << ")";
        return b64;
    }
    throw std::runtime_error(std::string("Unexpected JSON shape for ") + tagForLog);
}


void FileDownloadHandler::processSingleFile(qulonglong fileId)
{
    FD_LOG("begin") << "processing file_id=" << fileId;
    try {
        // 1) look up FileClientData (owner-only path)
        FileClientData *fcd = store->getFileData(fileId);
        if (!fcd) {
            FD_LOG("owner-check") << "file_id not owned locally – shared path NYI";
            emit downloadResult("Error",
                                QString("File %1 not in local store (shared download not implemented)")
                                    .arg(fileId));
            return;
        }
        FD_LOG("owner-check") << "found FileClientData (filename="
                              << QString::fromStdString(fcd->filename) << ")";

        // 2) body JSON
        nlohmann::json jBody; jBody["file_id"] = static_cast<uint64_t>(fileId);
        std::string bodyStr = jBody.dump();
        FD_LOG("json") << "request body =" << QString::fromStdString(bodyStr);

        // 3) auth headers
        auto maybeUser = store->getUser();
        if (!maybeUser.has_value()) throw std::runtime_error("No logged-in user");
        const auto &userInfo  = *maybeUser;
        const auto &username  = userInfo.username;
        const auto &privBundle= userInfo.fullBundle;

        auto headers = NetworkAuthUtils::makeAuthHeaders(
            username, privBundle,
            "POST", "/api/fs/download", bodyStr);

        FD_LOG("auth") << "built headers: "
                       << QString::fromStdString(headers["X-Timestamp"]);

        // 4) HTTP POST
        HttpRequest req(HttpRequest::Method::POST, "/api/fs/download", bodyStr, headers);
        AsioHttpClient client; client.init("");
        FD_LOG("network") << "sending request to server …";
        HttpResponse resp = client.sendRequest(req);
        FD_LOG("network") << "HTTP status =" << resp.statusCode
                          << " body bytes =" << resp.body.size();

        if (resp.statusCode != 200) {
            emit downloadResult("Error",
                                QString("Server returned %1 for file %2").arg(resp.statusCode).arg(fileId));
            return;
        }

        // 5) parse JSON
        nlohmann::json jResp = nlohmann::json::parse(resp.body);
        bool isOwner = jResp.at("is_owner").get<bool>();
        FD_LOG("json") << "is_owner =" << isOwner;
        if (!isOwner) {
            emit downloadResult("Info",
                                QString("File %1 is shared; client lacks sharing support").arg(fileId));
            return;
        }

        std::string fileB64  = fieldToBase64(jResp.at("file_content"), "file_content");
        std::string metaB64  = fieldToBase64(jResp.at("metadata"),     "metadata");
        std::string edSigB64 = jResp.at("pre_quantum_signature").get<std::string>();
        std::string pqSigB64 = jResp.at("post_quantum_signature").get<std::string>();
        FD_LOG("json") << "cipher sizes (base64) – file="
                       << fileB64.size() << " meta=" << metaB64.size();

        // 6) verify signatures
        std::string verifyErr;
        if (!verifySignatures(username, fileB64, metaB64,
                              edSigB64, pqSigB64,
                              userInfo.publicBundle, verifyErr)) {
            FD_LOG("verify") << "failed (" << QString::fromStdString(verifyErr) << ")";
            emit downloadResult("Error",
                                QString("Signature verification failed: %1").arg(
                                    QString::fromStdString(verifyErr)));
            return;
        }
        FD_LOG("verify") << "signatures OK";

        // 7) decrypt
        std::vector<uint8_t> fileCipher = FileClientData::base64_decode(fileB64);
        std::vector<uint8_t> metaCipher = FileClientData::base64_decode(metaB64);
        FD_LOG("decrypt") << "cipher sizes – file=" << fileCipher.size()
                          << " meta=" << metaCipher.size();

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

        FD_LOG("decrypt") << "plaintext sizes – file="
                          << plainFile.data.size() << " meta=" << plainMeta.data.size();

        // 8) filename from meta
        std::string fileName = fcd->filename;
        try {
            nlohmann::json jMeta = nlohmann::json::parse(
                std::string(reinterpret_cast<char*>(plainMeta.data.data()),
                            plainMeta.data.size()));
            fileName = jMeta.value("filename", fileName);
        } catch (...) {
            FD_LOG("meta") << "metadata JSON parse failed, keeping stored filename";
        }
        FD_LOG("meta") << "resolved filename =" << QString::fromStdString(fileName);

        QByteArray ba(reinterpret_cast<const char*>(plainFile.data.data()),
                      static_cast<int>(plainFile.data.size()));

        if (!saveToDownloads(QString::fromStdString(fileName), ba)) {
            emit downloadResult("Error", "Could not write into Downloads folder");
            return;
        }

        emit downloadResult("Success",
                            QString("Saved to Downloads (%1 bytes)").arg(ba.size()));
        // You may still emit fileReady if QML needs the bytes in-memory:
        emit fileReady(fileId, QString::fromStdString(fileName), ba);
    }
    catch (const std::exception &ex) {
        FD_LOG("exception") << ex.what();
        emit downloadResult("Exception", QString::fromUtf8(ex.what()));
    }
}

bool FileDownloadHandler::verifySignatures(const std::string &username,
                                           const std::string &fileB64,
                                           const std::string &metaB64,
                                           const std::string &edSigB64,
                                           const std::string &pqSigB64,
                                           const KeyBundle   &pubBundle,
                                           std::string       &outError)
{
    // ─── Decode ciphertexts ────────────────────────────────────────────────
    std::vector<uint8_t> fileCipher = FileClientData::base64_decode(fileB64);
    std::vector<uint8_t> metaCipher = FileClientData::base64_decode(metaB64);

    // ─── Rebuild canonical string  username|sha256(file)|sha256(meta) ──────
    std::string fileHashHex = toHex(Hash::sha256(fileCipher));   // lower-case hex
    std::string metaHashHex = toHex(Hash::sha256(metaCipher));
    std::ostringstream oss;
    oss << username << '|' << fileHashHex << '|' << metaHashHex;
    std::string canonical = oss.str();
    std::vector<uint8_t> msgBytes(canonical.begin(), canonical.end());

#ifdef SIG_DEBUG
    auto dumpHex = [](const std::vector<uint8_t>& v) {
        std::ostringstream h; h << std::hex << std::setfill('0');
        for (uint8_t b : v) h << std::setw(2) << static_cast<int>(b);
        return h.str();
    };
    FD_LOG("sig") << "canonical =«" << QString::fromStdString(canonical) << "»";
#endif

    // ─── Ed25519 verification ──────────────────────────────────────────────
    std::vector<uint8_t> edSig   = FileClientData::base64_decode(edSigB64);
    const auto&          edPub   = pubBundle.getEd25519Pub();   // 32-byte raw

    Signer_Ed verifierEd;
    verifierEd.loadPublicKey(edPub.data(), edPub.size());

#ifdef SIG_DEBUG
    FD_LOG("sig") << "Ed25519 pub = " << QString::fromStdString(dumpHex(edPub))
                  << "  sigLen = "   << edSig.size();
#endif

    if (!verifierEd.verify(msgBytes, edSig)) {
        outError = "Ed25519 failed";
        return false;
    }

    // ─── Dilithium verification ────────────────────────────────────────────
    std::vector<uint8_t> pqSig = FileClientData::base64_decode(pqSigB64);
    const auto&          pqPub = pubBundle.getDilithiumPub();   // 2 592 B

    Signer_Dilithium verifierPQ;
    verifierPQ.loadPublicKey(pqPub.data(), pqPub.size());

#ifdef SIG_DEBUG
    FD_LOG("sig") << "Dilithium sigLen = " << pqSig.size();
#endif

    if (!verifierPQ.verify(msgBytes, pqSig)) {
        outError = "Dilithium failed";
        return false;
    }

    return true;   // both signatures OK
}

