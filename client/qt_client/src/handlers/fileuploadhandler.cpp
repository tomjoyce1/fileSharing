#include "FileUploadHandler.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <QFileInfo>
#include <QMetaObject>    // for QMetaObject::invokeMethod
#include <QDebug>

// NEW: hash helper
#include "../utils/crypto/Hash.h"

namespace {
// ──────────────────────────────────────────────────────────────────────────
// Convert a byte vector to lower‑case hex (two chars per byte, no 0x).
// This matches Node's `digest('hex')` output.
// ──────────────────────────────────────────────────────────────────────────
std::string toHex(const std::vector<uint8_t>& data) {
    static const char* lut = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(lut[b >> 4]);
        out.push_back(lut[b & 0x0F]);
    }
    return out;
}
} // namespace

FileUploadHandler::FileUploadHandler(ClientStore* store, QObject* parent)
    : QObject(parent)
    , m_store(store)
{
    // Attempt to load the user from the store:
    auto maybeUser = m_store->getUser();
    if (!maybeUser.has_value()) {
        qWarning() << "[FileUploadHandler] No user registered; cannot upload.";
        return;
    }
    m_username = maybeUser->username;
    m_keybundle = maybeUser->keybundle;
}

void FileUploadHandler::uploadFiles(const QStringList& fileUrls)
{
    // Capture 'this' pointer so lambdas can call methods/signals
    FileUploadHandler* self = this;

    // Run on a separate thread so UI stays responsive:
    std::async(std::launch::async, [self, fileUrls]() {
        for (const QString& qurl : fileUrls) {
            std::string localPath = qurl.toStdString();
            try {
                uint64_t file_id = self->processSingleFile(localPath);
                if (file_id == 0) {
                    // Notify QML of failure
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
    qDebug() << "[TRACE] processSingleFile() start: " << QString::fromStdString(localPath);

    // ── 1) Read the raw file bytes from disk ──────────────────────────────────
    qDebug() << "[TRACE] 1) readFileBytes()";
    std::vector<uint8_t> plaintext = readFileBytes(localPath);
    if (plaintext.empty()) {
        qWarning() << "[ERROR] readFileBytes returned empty for"
                   << QString::fromStdString(localPath);
        return 0;
    }
    qDebug() << "[TRACE]   → readFileBytes succeeded, size =" << plaintext.size();

    // ── 2) Construct fresh FileClientData (random FEK, MEK, nonces) ─────────
    qDebug() << "[TRACE] 2) FileClientData constructor (generate=true)";
    FileClientData fcd(true);
    qDebug() << "[TRACE]   → FEK and MEK and nonces generated";

    // ── 3) Encrypt the file contents with AES-256-CTR ─────────────────────────
    qDebug() << "[TRACE] 3) Symmetric::encrypt(file, FEK)";
    Symmetric::Ciphertext encFile;
    try {
        encFile = Symmetric::encrypt(
            plaintext,
            std::vector<uint8_t>(fcd.fek.begin(), fcd.fek.end())
            );
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] Symmetric::encrypt(file) threw:" << ex.what();
        return 0;
    }
    fcd.file_nonce.fill(0);
    std::copy(encFile.iv.begin(), encFile.iv.end(), fcd.file_nonce.begin());
    qDebug() << "[TRACE]   → file encrypted; ciphertext bytes =" << encFile.data.size();

    // ── 4) Build a tiny metadata JSON: { filename, filesize } ────────────────
    qDebug() << "[TRACE] 4) Build metadata JSON";
    json jmeta;
    try {
        jmeta["filename"] = QFileInfo(QString::fromStdString(localPath)).fileName().toStdString();
        jmeta["filesize"] = plaintext.size();
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] building metadata JSON threw:" << ex.what();
        return 0;
    }
    std::string metaPlain = jmeta.dump();
    qDebug() << "[TRACE]   → metadata JSON =" << QString::fromStdString(metaPlain);

    // ── 5) Encrypt metadata JSON with AES-256-CTR ────────────────────────────
    qDebug() << "[TRACE] 5) Symmetric::encrypt(metadata, MEK)";
    Symmetric::Ciphertext encMeta;
    try {
        std::vector<uint8_t> metaBytes(metaPlain.begin(), metaPlain.end());
        encMeta = Symmetric::encrypt(
            metaBytes,
            std::vector<uint8_t>(fcd.mek.begin(), fcd.mek.end())
            );
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] Symmetric::encrypt(metadata) threw:" << ex.what();
        return 0;
    }
    fcd.metadata_nonce.fill(0);
    std::copy(encMeta.iv.begin(), encMeta.iv.end(), fcd.metadata_nonce.begin());
    qDebug() << "[TRACE]   → metadata encrypted; ciphertext bytes =" << encMeta.data.size();

    // ── 6) Base64‑encode only ciphertext bytes (not IVs) ─────────────────────
    qDebug() << "[TRACE] 6) Base64‑encode ciphertexts";
    auto encodeB64 = [&](const std::vector<uint8_t>& buf) {
        return FileClientData::base64_encode(buf.data(), buf.size());
    };
    std::string fileB64, metaB64;
    try {
        fileB64 = encodeB64(encFile.data);
        metaB64 = encodeB64(encMeta.data);
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] base64_encode threw:" << ex.what();
        return 0;
    }
    qDebug() << "[TRACE]   → fileB64 length =" << int(fileB64.size())
             << ", metaB64 length =" << int(metaB64.size());

    // ── 7) Build the signature input = username|sha256(encFile)|sha256(encMeta)
    qDebug() << "[TRACE] 7) buildSignatureInput()";
    std::string sigInput = buildSignatureInput(m_username, fileB64, metaB64);
    std::vector<uint8_t> msgBytes(sigInput.begin(), sigInput.end());
    qDebug() << "[TRACE]   → signature input length =" << int(msgBytes.size());

    // ── 8) ED25519 sign that sigInput ────────────────────────────────────────
    // (unchanged code follows) ------------------------------------------------
    qDebug() << "[TRACE] 8) ED25519 sign";
    std::string edPrivB64;
    std::vector<uint8_t> edPrivRaw;
    try {
        edPrivB64  = m_keybundle.getEd25519PrivateKeyBase64();
        edPrivRaw  = FileClientData::base64_decode(edPrivB64);
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] decoding ED25519 private key threw:" << ex.what();
        return 0;
    }
    if (edPrivRaw.size() != static_cast<size_t>(crypto_sign_SECRETKEYBYTES)) {
        qWarning() << "[ERROR] ED25519 private‑key length is wrong:" << edPrivRaw.size();
        return 0;
    }

    Signer_Ed signerEd;
    try {
        signerEd.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] signerEd.loadPrivateKey() threw:" << ex.what();
        return 0;
    }

    std::vector<uint8_t> edSig;
    try {
        edSig = signerEd.sign(msgBytes);
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] signerEd.sign() threw:" << ex.what();
        return 0;
    }
    std::string edSigB64 = FileClientData::base64_encode(edSig.data(), edSig.size());

    // ── 9) Dilithium sign (unchanged apart from msgBytes) -------------------
    qDebug() << "[TRACE] 9) Dilithium sign";
    std::string pqPrivB64;
    std::vector<uint8_t> pqPrivRaw;
    try {
        pqPrivB64  = m_keybundle.getDilithiumPrivateKeyBase64();
        pqPrivRaw  = FileClientData::base64_decode(pqPrivB64);
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] decoding Dilithium private key threw:" << ex.what();
        return 0;
    }
    Signer_Dilithium probeDil;
    if (pqPrivRaw.size() != probeDil.skLength()) {
        qWarning() << "[ERROR] Dilithium private‑key length is wrong:" << pqPrivRaw.size();
        return 0;
    }

    Signer_Dilithium signerPQ;
    try {
        signerPQ.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] signerPQ.loadPrivateKey() threw:" << ex.what();
        return 0;
    }

    std::vector<uint8_t> pqSig;
    try {
        pqSig = signerPQ.sign(msgBytes);
    }
    catch (const std::exception& ex) {
        qWarning() << "[ERROR] signerPQ.sign() threw:" << ex.what();
        return 0;
    }
    std::string pqSigB64 = FileClientData::base64_encode(pqSig.data(), pqSig.size());

    // ── 10) Build body JSON --------------------------------------------------
    nlohmann::ordered_json jbody;
    jbody["file_content"]           = fileB64;
    jbody["metadata"]               = metaB64;
    jbody["pre_quantum_signature"]  = edSigB64;
    jbody["post_quantum_signature"] = pqSigB64;

    std::string bodyString = jbody.dump();

    // ── 11) Canonical request string & auth headers (unchanged) -------------
    const QString qsNow = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    std::string timestamp = qsNow.toStdString();
    std::ostringstream canon;
    canon << m_username << "|" << timestamp << "|POST|/api/fs/upload|" << bodyString;
    const std::string canonicalString = canon.str();

    std::vector<uint8_t> preAuthSig; // Ed25519(canonicalString)
    std::vector<uint8_t> postAuthSig; // Dilithium(canonicalString)
    {
        Signer_Ed signerEdAuth;
        signerEdAuth.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
        preAuthSig = signerEdAuth.sign({ canonicalString.begin(), canonicalString.end() });
    }
    {
        Signer_Dilithium signerPQAuth;
        signerPQAuth.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
        postAuthSig = signerPQAuth.sign({ canonicalString.begin(), canonicalString.end() });
    }

    std::string preAuthSigB64  = FileClientData::base64_encode(preAuthSig.data(),  preAuthSig.size());
    std::string postAuthSigB64 = FileClientData::base64_encode(postAuthSig.data(), postAuthSig.size());
    std::string combinedAuthSig = preAuthSigB64 + "||" + postAuthSigB64;

    std::map<std::string, std::string> headers = {
        { "Host",           "localhost:3000" },
        { "Content-Type",   "application/json" },
        { "X-Username",     m_username        },
        { "X-Timestamp",    timestamp         },
        { "X-Signature",    combinedAuthSig   }
    };

    // ── 12) Send the HTTP POST ----------------------------------------------
    HttpRequest req(HttpRequest::Method::POST, "/api/fs/upload", bodyString, headers);
    AsioHttpClient httpClient;
    httpClient.init(""); // no TLS
    HttpResponse resp = httpClient.sendRequest("localhost", 3000, req);

    qDebug() << "[CLIENT]   → HTTP status code =" << resp.statusCode;
    qDebug() << "[CLIENT]   → HTTP body =" << QString::fromStdString(resp.body);

    if (resp.statusCode == 201) {
        uint64_t newFileId = 0;
        try {
            auto respJson = json::parse(resp.body);
            newFileId = respJson.at("file_id").get<uint64_t>();
        } catch (const std::exception& ex) {
            qWarning() << "[ERROR] parsing response JSON threw:" << ex.what();
            return 0;
        }

        fcd.file_id = newFileId;
        m_store->upsertFileData(fcd);
        return newFileId;
    }

    qWarning() << "[ERROR] server returned non‑201 status:" << resp.statusCode;
    return 0;
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
    // NEW: match server‑side helper -> hash(ciphertext) & hash(ciphertext‑metadata)

    // 1) Decode base64 back to ciphertext bytes
    std::vector<uint8_t> fileCipher  = FileClientData::base64_decode(fileB64);
    std::vector<uint8_t> metaCipher  = FileClientData::base64_decode(metaB64);

    // 2) SHA‑256 each blob
    std::string fileHashHex = toHex(Hash::sha256(fileCipher));
    std::string metaHashHex = toHex(Hash::sha256(metaCipher));

    // 3) Concatenate with pipes
    std::ostringstream oss;
    oss << uname << "|" << fileHashHex << "|" << metaHashHex;
    return oss.str();
}
