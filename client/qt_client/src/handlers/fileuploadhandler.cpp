#include "FileUploadHandler.h"
#include <QFileInfo>
#include <QDateTime>
#include <QMetaObject>
#include <QDebug>
#include <sstream>
#include <system_error>
#include <fstream>


// Static helper to convert a byte‐vector into lowercase hex
namespace {
static std::string toHex(const std::vector<uint8_t>& data) {
    static const char* lut = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(lut[b >> 4]);
        out.push_back(lut[b & 0x0F]);
    }
    return out;
}
}


FileUploadHandler::FileUploadHandler(ClientStore* store, QObject* parent)
    : QObject(parent), store(store)
{
    // Load user (username + KeyBundle) from the store:
    auto user = store->getUser();
    if (!user.has_value()) {
        qWarning() << "[FileUploadHandler] No user registered; cannot upload.";
        return;
    }
    username = user->username;
    keybundle = user->keybundle;
}

void FileUploadHandler::uploadFiles(const QStringList& fileUrls)
{
    FileUploadHandler* self = this;

    // Run in background; each fileUrl is processed sequentially in that thread
    HandlerUtils::runAsync([self, fileUrls] {
        for (const QString& qurl : fileUrls) {
            std::string localPath = qurl.toStdString();
            try {
                // Process that file
                uint64_t file_id = self->processSingleFile(localPath);
                if (file_id == 0) {
                    QString msg = QString("Failed to upload %1").arg(qurl);
                    QMetaObject::invokeMethod(
                        self,
                        [self, msg]() { emit self->uploadResult("Error", msg); },
                        Qt::QueuedConnection
                        );
                } else {
                    QString msg = QString("Uploaded %1 (id=%2)")
                                      .arg(qurl).arg(file_id);
                    QMetaObject::invokeMethod(
                        self,
                        [self, msg]() { emit self->uploadResult("Success", msg); },
                        Qt::QueuedConnection
                        );
                }
            }
            catch (const std::exception& ex) {
                QString msg = QString("Exception for %1: %2")
                                  .arg(qurl, QString::fromStdString(ex.what()));
                QMetaObject::invokeMethod(
                    self,
                    [self, msg]() { emit self->uploadResult("Exception", msg); },
                    Qt::QueuedConnection
                    );
            }
        }
    });
}

uint64_t FileUploadHandler::processSingleFile(const std::string& localPath)
{
    // Read the file bytes
    std::vector<uint8_t> plaintext = readFileBytes(localPath);
    if (plaintext.empty()) {
        qWarning() << "[ERROR]" << "readFileBytes returned empty for"
                   << QString::fromStdString(localPath);
        return 0ULL;
    }

    // Construct FileClientData with random values
    FileClientData fcd(true);
    fcd.filename = QFileInfo(QString::fromStdString(localPath)).fileName().toStdString();

    // Encrypt file contents with AES-256-CTR
    Symmetric::Ciphertext encFile; // Ciphertext struct
    try {
        encFile = Symmetric::encrypt(
            plaintext,
            std::vector<uint8_t>(fcd.fek.begin(), fcd.fek.end())
            );
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "Symmetric::encrypt(file) threw:" << ex.what();
        return 0ULL;
    }

    // Copy IV into fcd.file_nonce
    fcd.file_nonce.fill(0);
    std::copy(encFile.iv.begin(), encFile.iv.end(), fcd.file_nonce.begin());

    // Build metadata JSON
    nlohmann::json jmeta;
    try {
        jmeta["filename"] = fcd.filename;
        jmeta["filesize"] = plaintext.size();
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "building metadata JSON threw:" << ex.what();
        return 0ULL;
    }
    std::string metaPlain = jmeta.dump();

    // Encrypt metadata JSON with AES-256-CTR
    Symmetric::Ciphertext encMeta;
    try {
        std::vector<uint8_t> metaBytes(metaPlain.begin(), metaPlain.end());
        encMeta = Symmetric::encrypt(
            metaBytes,
            std::vector<uint8_t>(fcd.mek.begin(), fcd.mek.end())
            );
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "Symmetric::encrypt(metadata) threw:" << ex.what();
        return 0ULL;
    }

    // Copy IV into fcd.metadata_nonce
    fcd.metadata_nonce.fill(0);
    std::copy(encMeta.iv.begin(), encMeta.iv.end(), fcd.metadata_nonce.begin());

    // Base64‐encode only the ciphertext bytes
    auto encodeB64 = [&](const std::vector<uint8_t>& buf) {
        return FileClientData::base64_encode(buf.data(), buf.size());
    };
    std::string fileB64, metaB64;
    try {
        fileB64 = encodeB64(encFile.data);
        metaB64 = encodeB64(encMeta.data);
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "base64_encode threw:" << ex.what();
        return 0ULL;
    }


    // Build the signature input (username|sha256(fileCipher)|sha256(metaCipher))
    std::string sigInput = buildSignatureInput(username, fileB64, metaB64);
    std::vector<uint8_t> msgBytes(sigInput.begin(), sigInput.end());


    // Ed25519 sign that sigInput
    std::string edPrivB64 = keybundle.getEd25519PrivateKeyBase64();
    std::vector<uint8_t> edPrivRaw = FileClientData::base64_decode(edPrivB64);
    Signer_Ed signerEd;
    signerEd.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
    std::vector<uint8_t> edSig = signerEd.sign(msgBytes);
    std::string edSigB64 = FileClientData::base64_encode(edSig.data(), edSig.size());

    // Dilithium sign that sigInput
    std::string pqPrivB64 = keybundle.getDilithiumPrivateKeyBase64();
    std::vector<uint8_t> pqPrivRaw = FileClientData::base64_decode(pqPrivB64);
    Signer_Dilithium signerPQ;
    signerPQ.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
    std::vector<uint8_t> pqSig = signerPQ.sign(msgBytes);
    std::string pqSigB64 = FileClientData::base64_encode(pqSig.data(), pqSig.size());

    // Build body JSON (it has to be in this specifc order!)
    nlohmann::ordered_json jbody;
    jbody["file_content"]           = fileB64;
    jbody["metadata"]               = metaB64;
    jbody["pre_quantum_signature"]  = edSigB64;
    jbody["post_quantum_signature"] = pqSigB64;
    std::string bodyString = jbody.dump();


    // Build auth headers
    auto headers = NetworkAuthUtils::makeAuthHeaders(
        username,
        keybundle,
        "POST",
        "/api/fs/upload",
        bodyString
        );

    // Build request (no need to add Host manually; toString() will do it)
    HttpRequest req(HttpRequest::Method::POST, "/api/fs/upload", bodyString, headers);

    AsioHttpClient client;
    client.init("");
    HttpResponse resp = client.sendRequest(req);   // uses Config::instance().serverHost/port

    qDebug() << "[CLIENT]" << "→ HTTP status code =" << resp.statusCode;
    qDebug() << "[CLIENT]" << "→ HTTP body =" << QString::fromStdString(resp.body);

    if (resp.statusCode == 201) {
        // Parse response JSON to extract file_id
        uint64_t newFileId = 0;
        try {
            auto respJson = nlohmann::json::parse(resp.body);
            newFileId = respJson.at("file_id").get<uint64_t>();
        }
        catch (const std::exception& ex) {
            qWarning() << "[ERROR]" << "parsing response JSON threw:" << ex.what();
            return 0ULL;
        }

        // On success store FileClientData
        fcd.file_id = newFileId;
        store->upsertFileData(fcd);
        return newFileId;
    }

    // On error
    return 0ULL;
}

std::vector<uint8_t> FileUploadHandler::readFileBytes(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return {};

    in.seekg(0, std::ios::end);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size <= 0) return {};

    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(data.data()), size)) {
        return {};
    }
    return data;
}

std::string FileUploadHandler::buildSignatureInput(const std::string& uname,
                                                   const std::string& fileB64,
                                                   const std::string& metaB64)
{
    // Decode base64 back to ciphertext
    std::vector<uint8_t> fileCipher = FileClientData::base64_decode(fileB64);
    std::vector<uint8_t> metaCipher = FileClientData::base64_decode(metaB64);

    // SHA‐256 each
    std::string fileHashHex = toHex(Hash::sha256(fileCipher));
    std::string metaHashHex = toHex(Hash::sha256(metaCipher));

    // Concatenate: uname|fileHashHex|metaHashHex
    std::ostringstream oss;
    oss << uname << "|" << fileHashHex << "|" << metaHashHex;
    return oss.str();
}
