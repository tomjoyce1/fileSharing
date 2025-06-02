#include "FileUploadHandler.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <QFileInfo>
#include <QMetaObject>    // for QMetaObject::invokeMethod
#include <QDebug>

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

    // ── 6) Base64-encode *only* the ciphertext bytes (not the IVs) ───────────
    qDebug() << "[TRACE] 6) Base64‐encode ciphertexts";
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

    // ── 7) Build the “file_signature_input” = userId|fileB64|metaB64 ─────────
    qDebug() << "[TRACE] 7) buildSignatureInput()";
    std::string sigInput = buildSignatureInput(m_username, fileB64, metaB64);
    std::vector<uint8_t> msgBytes(sigInput.begin(), sigInput.end());
    qDebug() << "[TRACE]   → signature input length =" << int(msgBytes.size());

    // ── 8) ED25519 sign that sigInput using *your registered* private key ───
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
        qWarning() << "[ERROR] ED25519 private‐key length is wrong:"
                   << edPrivRaw.size() << "bytes (expected" << crypto_sign_SECRETKEYBYTES << ")";
        return 0;
    }
    qDebug() << "[TRACE]   → ED25519 private key raw size =" << edPrivRaw.size();

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
    qDebug() << "[TRACE]   → edSig size =" << edSig.size()
             << ", edSigB64 length =" << edSigB64.size();

    // ── 9) DILITHIUM sign that same sigInput using *your registered* private key ─
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
    // Check length matches length_secret_key
    Signer_Dilithium probeDil;
    size_t expectedSkLen = probeDil.skLength();
    if (pqPrivRaw.size() != expectedSkLen) {
        qWarning() << "[ERROR] Dilithium private‐key length is wrong:"
                   << pqPrivRaw.size() << "bytes (expected" << expectedSkLen << ")";
        return 0;
    }
    qDebug() << "[TRACE]   → Dilithium private key raw size =" << pqPrivRaw.size();

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
    qDebug() << "[TRACE]   → pqSig size =" << pqSig.size()
             << ", pqSigB64 length =" << pqSigB64.size();

    // ── 10) Build **one** raw JSON string, exactly in this order:
    nlohmann::json jbody;
    jbody["file_content"]           = fileB64;
    jbody["metadata"]               = metaB64;
    jbody["pre_quantum_signature"]  = edSigB64;
    jbody["post_quantum_signature"] = pqSigB64;

    // Dump the JSON text ONE TIME and store it verbatim:
    std::string bodyString = jbody.dump(/* you may pass no arguments to ensure no extra whitespace */);
    qDebug() << "[CLIENT] bodyString (len=" << bodyString.size() << "):"
             << QString::fromStdString(bodyString);

    // ── 11) Build canonical = username|timestamp|POST|/api/fs/upload|bodyString
    //      Make sure we use exactly the same path that the server sees:
    const QString qsNow = QDateTime::currentDateTimeUtc().toString(Qt::ISODate) + "Z";
    std::string timestamp = qsNow.toStdString();
    std::ostringstream canon;
    canon << m_username      // “alice”, for example
          << "|" << timestamp // e.g. “2025-06-02T18:47:12Z”
          << "|" << "POST"
          << "|" << "/api/fs/upload"
          << "|" << bodyString;
    const std::string canonicalString = canon.str();
    qDebug() << "[CLIENT] canonicalString (len=" << canonicalString.size() << "):"
             << QString::fromStdString(canonicalString);

    // ── 12) Sign “canonicalString” with Ed25519 and Dilithium (post‐quantum)
    //      exactly as Bun’s helper does. For example:
    std::vector<uint8_t> preAuthSig;   // raw bytes of Ed25519(canonicalString)
    std::vector<uint8_t> postAuthSig;  // raw bytes of Dilithium(canonicalString)

    {
        // (a) Ed25519:
        Signer_Ed signerEd;
        signerEd.loadPrivateKey(edPrivRaw.data(), edPrivRaw.size());
        preAuthSig = signerEd.sign(
            std::vector<uint8_t>(canonicalString.begin(),
                                 canonicalString.end())
            );
    }

    {
        // (b) Dilithium:
        Signer_Dilithium signerPQ;
        signerPQ.loadPrivateKey(pqPrivRaw.data(), pqPrivRaw.size());
        postAuthSig = signerPQ.sign(
            std::vector<uint8_t>(canonicalString.begin(),
                                 canonicalString.end())
            );
    }

    // Base64‐encode each:
    std::string preAuthSigB64  = FileClientData::base64_encode(preAuthSig.data(),  preAuthSig.size());
    std::string postAuthSigB64 = FileClientData::base64_encode(postAuthSig.data(), postAuthSig.size());
    std::string combinedAuthSig = preAuthSigB64 + "||" + postAuthSigB64;
    qDebug() << "[CLIENT] combinedAuthSig length =" << combinedAuthSig.size();

    // ── 13) Build headers exactly as Bun expects:
    //
    //     "Content-Type":    "application/json"
    //     "Host":            "localhost:3000"
    //     "X-Username":      m_username
    //     "X-Timestamp":     timestamp
    //     "X-Signature":     combinedAuthSig
    //
    std::map<std::string, std::string> headers = {
        { "Host",           "localhost:3000" },
        { "Content-Type",   "application/json" },
        { "X-Username",     m_username        },
        { "X-Timestamp",    timestamp         },
        { "X-Signature",    combinedAuthSig   }
    };

    // ── 14) Send the HTTP POST to “/api/fs/upload”
    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/fs/upload",
        bodyString,
        headers
        );

    AsioHttpClient httpClient;
    httpClient.init(""); // no TLS
    HttpResponse resp = httpClient.sendRequest("localhost", 3000, req);

    qDebug() << "[CLIENT]   → HTTP status code =" << resp.statusCode;
    qDebug() << "[CLIENT]   → HTTP body =" << QString::fromStdString(resp.body);


    if (resp.statusCode == 201) {
        qDebug() << "[TRACE] 15) server returned 201, parsing file_id";
        uint64_t newFileId = 0;
        try {
            auto respJson = json::parse(resp.body);
            newFileId = respJson.at("file_id").get<uint64_t>();
        }
        catch (const std::exception& ex) {
            qWarning() << "[ERROR] parsing response JSON threw:" << ex.what();
            return 0;
        }

        // ── 16) Persist FileClientData locally ────────────────────────────────
        fcd.file_id = newFileId;
        qDebug() << "[TRACE] 16) upsertFileData (file_id =" << newFileId << ")";
        m_store->upsertFileData(fcd);

        qDebug() << "[TRACE] processSingleFile() finished → returning" << newFileId;
        return newFileId;
    }

    qWarning() << "[ERROR] server returned non‐201 status:" << resp.statusCode;
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
    std::ostringstream oss;
    oss << uname << "|" << fileB64 << "|" << metaB64;
    return oss.str();
}
