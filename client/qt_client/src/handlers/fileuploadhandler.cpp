#include "FileUploadHandler.h"
#include "../utils/handlerutils.h"
#include "../utils/NetworkAuthUtils.h"
#include <QFileInfo>
#include <QDateTime>
#include <QMetaObject>
#include <QDebug>
#include <sstream>
#include <system_error>
#include <fstream>

namespace {

// ─────────────────────────────────────────────────────────────────────────
// Inline helper: convert a byte vector to lowercase hex string
// (used instead of a separate toHex function)
// ─────────────────────────────────────────────────────────────────────────
static std::string bytesToHex(const std::vector<uint8_t>& data) {
    static const char* lut = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(lut[b >> 4]);
        out.push_back(lut[b & 0x0F]);
    }
    return out;
}

} // namespace (private)


FileUploadHandler::FileUploadHandler(ClientStore* store, QObject* parent)
    : QObject(parent), store(store)
{
}


void FileUploadHandler::uploadFiles(const QStringList& fileUrls)
{
    FileUploadHandler* self = this;

    // Run each upload in a background thread sequentially
    HandlerUtils::runAsync([self, fileUrls] {
        for (const QString& qurl : fileUrls) {
            std::string localPath = qurl.toStdString();
            try {
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

// Returns File id
uint64_t FileUploadHandler::processSingleFile(const std::string& localPath)
{
    // Read file
    std::vector<uint8_t> plaintext = readFileBytes(localPath);
    if (plaintext.empty()) {
        qWarning() << "[ERROR]" << "readFileBytes returned empty for"
                   << QString::fromStdString(localPath);
        return 0;
    }

    // Create FileClientData (generates random FEK & MEK)
    FileClientData fcd(true);
    fcd.filename = QFileInfo(QString::fromStdString(localPath))
                       .fileName()
                       .toStdString();

    // Encrypt file contents under FEK (AES-256-CTR)
    std::array<uint8_t, 16> fileNonce{};
    Symmetric::Ciphertext encFile;
    try {
        encFile = encryptFileContent(plaintext, fcd.fek, fileNonce);
        fcd.file_nonce = fileNonce;
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "encryptFileContent threw:" << ex.what();
        return 0;
    }

    std::string metaPlain = buildPlainMetadata(fcd.filename, plaintext.size());

    // Encrypt metadata under MEK (AES-256-CTR)
    std::array<uint8_t, 16> metaNonce{};
    Symmetric::Ciphertext encMeta;
    try {
        encMeta = encryptMetadata(metaPlain, fcd.mek, metaNonce);
        fcd.metadata_nonce = metaNonce;
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "encryptMetadata threw:" << ex.what();
        return 0ULL;
    }

    // Fetch logged-in user’s username + KeyBundle from ClientStore
    auto maybeUser = store->getUser();
    if (!maybeUser.has_value()) {
        throw std::runtime_error("No logged-in user when trying to sign upload");
    }
    const auto& userInfo   = *maybeUser;
    const auto& keybundle  = userInfo.fullBundle;
    const auto& username   = userInfo.username;

    // TODO remove later
    std::string edB64 = keybundle.getEd25519PrivateKeyBase64();
    std::vector<uint8_t> edRaw = FileClientData::base64_decode(edB64);
    qDebug().nospace() << "[FileUploadHandler] before encrypting ‘"
                       << localPath.c_str()
                       << "’, username=" << username.c_str()
                       << ", ed25519PrivB64 length=" << edB64.length()
                       << ", raw bytes=" << edRaw.size();

    if (edRaw.size() != crypto_sign_SECRETKEYBYTES) {
        qWarning().nospace() << "[FileUploadHandler] WARNING: ed25519Priv is not 64 bytes!";
        // (You might even return 0 here to abort.)
    }


    /// Compute SHA-256 over the raw ciphertext
    std::vector<uint8_t> fileHash = Hash::sha256(encFile.data);
    std::vector<uint8_t> metaHash = Hash::sha256(encMeta.data);

    // Convert each hash to lowercase hex
    std::string fileHashHex = bytesToHex(fileHash);
    std::string metaHashHex = bytesToHex(metaHash);

    // Now base64-encode for sending
    std::string fileB64 = base64Encode(encFile.data);
    std::string metaB64 = base64Encode(encMeta.data);

    std::ostringstream oss;
    oss << username << "|" << fileHashHex << "|" << metaHashHex;
    std::string sigInput = oss.str();
    std::vector<uint8_t> msgBytes(sigInput.begin(), sigInput.end());

    std::string edSigB64 = signWithEd25519(keybundle, msgBytes);
    std::string pqSigB64 = signWithDilithium(keybundle, msgBytes);

    // Build the JSON body for /api/fs/upload
    nlohmann::ordered_json jbody;
    jbody["file_content"]           = fileB64;
    jbody["metadata"]               = metaB64;
    jbody["pre_quantum_signature"]  = edSigB64;
    jbody["post_quantum_signature"] = pqSigB64;
    std::string bodyString = jbody.dump();

    auto headers = NetworkAuthUtils::makeAuthHeaders(
        username,
        keybundle,
        "POST",
        "/api/fs/upload",
        bodyString
        );

    HttpRequest req(HttpRequest::Method::POST,
                    "/api/fs/upload",
                    bodyString,
                    headers);
    AsioHttpClient client;
    client.init("");  // uses Config::instance().serverHost/port
    HttpResponse resp = client.sendRequest(req);

    qDebug() << "[CLIENT]" << "→ HTTP status code =" << resp.statusCode;
    qDebug() << "[CLIENT]" << "→ HTTP body =" << QString::fromStdString(resp.body);

    // On 201 Created, parse file_id and store FileClientData
    if (resp.statusCode != 201) {
        return 0;
    }

    uint64_t newFileId = 0;
    try {
        auto respJson = nlohmann::json::parse(resp.body);
        newFileId = respJson.at("file_id").get<uint64_t>();
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR]" << "parsing response JSON threw:" << ex.what();
        return 0;
    }

    fcd.file_id = newFileId;
    store->upsertFileData(fcd);
    return newFileId;
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


Symmetric::Ciphertext FileUploadHandler::encryptFileContent(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 32>& fek,
    std::array<uint8_t, 16>& outFileNonce)
{
    std::vector<uint8_t> fekVec(fek.begin(), fek.end());
    Symmetric::Ciphertext ct = Symmetric::encrypt(plaintext, fekVec);
    std::fill(outFileNonce.begin(), outFileNonce.end(), 0);
    std::copy(ct.iv.begin(), ct.iv.end(), outFileNonce.begin());
    return ct;
}


std::string FileUploadHandler::buildPlainMetadata(const std::string& filename,
                                                  size_t filesize)
{
    nlohmann::json jmeta;
    jmeta["filename"] = filename;
    jmeta["filesize"] = filesize;
    return jmeta.dump();
}


Symmetric::Ciphertext FileUploadHandler::encryptMetadata(
    const std::string& metaPlain,
    const std::array<uint8_t, 32>& mek,
    std::array<uint8_t, 16>& outMetadataNonce)
{
    std::vector<uint8_t> metaBytes(metaPlain.begin(), metaPlain.end());
    std::vector<uint8_t> mekVec(mek.begin(), mek.end());
    Symmetric::Ciphertext ct = Symmetric::encrypt(metaBytes, mekVec);
    std::fill(outMetadataNonce.begin(), outMetadataNonce.end(), 0);
    std::copy(ct.iv.begin(), ct.iv.end(), outMetadataNonce.begin());
    return ct;
}


std::string FileUploadHandler::base64Encode(const std::vector<uint8_t>& buf)
{
    return FileClientData::base64_encode(buf.data(), buf.size());
}


std::string FileUploadHandler::signWithEd25519(
    const KeyBundle& kb,
    const std::vector<uint8_t>& msg)
{
    std::string edPrivB64 = kb.getEd25519PrivateKeyBase64();
    std::vector<uint8_t> edPrivRaw = FileClientData::base64_decode(edPrivB64);

    qDebug().nospace() << "[signWithEd25519] edPrivB64 length=" << edPrivB64.length()
                       << ", raw bytes=" << edPrivRaw.size();


    if (edPrivRaw.size() != static_cast<size_t>(crypto_sign_SECRETKEYBYTES)) {
        throw std::runtime_error(
            "Ed25519 private key length is incorrect ("
            + std::to_string(edPrivRaw.size())
            + " bytes; expected "
            + std::to_string(crypto_sign_SECRETKEYBYTES)
            + ")"
            );
    }

    Signer_Ed signerEd;
    signerEd.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
    std::vector<uint8_t> edSig = signerEd.sign(msg);

    qDebug().nospace() << "[signWithEd25519] msg bytes=" << msg.size()
                       << ", edSig bytes=" << edSig.size();
    return FileClientData::base64_encode(edSig.data(), edSig.size());
}


std::string FileUploadHandler::signWithDilithium(
    const KeyBundle& kb,
    const std::vector<uint8_t>& msg)
{
    std::string pqPrivB64 = kb.getDilithiumPrivateKeyBase64();
    std::vector<uint8_t> pqPrivRaw = FileClientData::base64_decode(pqPrivB64);

    qDebug().nospace() << "[signWithDilithium] pqPrivB64 length=" << pqPrivB64.length()
                       << ", raw bytes=" << pqPrivRaw.size();

    Signer_Dilithium signerPQ;
    signerPQ.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
    std::vector<uint8_t> pqSig = signerPQ.sign(msg);

    qDebug().nospace() << "[signWithDilithium] msg bytes=" << msg.size()
                       << ", pqSig bytes=" << pqSig.size();

    return FileClientData::base64_encode(pqSig.data(), pqSig.size());
}
