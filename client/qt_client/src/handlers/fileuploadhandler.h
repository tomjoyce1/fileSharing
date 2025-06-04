#pragma once

#include <QObject>
#include <QStringList>
#include <nlohmann/json.hpp>
#include "../utils/ClientStore.h"
#include "../utils/crypto/FileClientData.h"
#include "../utils/crypto/KeyBundle.h"
#include "../utils/crypto/Symmetric.h"
#include "../utils/crypto/Signer_Ed.h"
#include "../utils/crypto/Signer_Dilithium.h"
#include "../utils/crypto/Hash.h"
#include "../utils/networking/AsioHttpClient.h"
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResponse.h"

/**
 * FileUploadHandler
 *
 * Exposes uploadFiles(fileUrls) to QML.  For each file:
 *   1. Read bytes from disk
 *   2. Build a new FileClientData (generates FEK, MEK, etc.)
 *   3. Encrypt file contents under FEK (AES-256-CTR)
 *   4. Encrypt metadata JSON (filename + size) under MEK (AES-256-CTR)
 *   5. Base64-encode ciphertexts
 *   6. Compute sha256(fileCipher) and sha256(metaCipher), convert to hex
 *   7. Sign “username|fileHashHex|metaHashHex” with Ed25519 & Dilithium
 *   8. Build JSON body and dual‐signature headers, send POST /api/fs/upload
 *   9. On 201 Created, parse returned file_id and store FileClientData in ClientStore
 *
 * The inlined code for building headers, sending the request, and handling the response
 * matches your existing logic exactly.  We keep base64Encode, signWithEd25519, and
 * signWithDilithium as private helpers.
 */
class FileUploadHandler : public QObject {
    Q_OBJECT

public:
    explicit FileUploadHandler(ClientStore* store, QObject* parent = nullptr);
    ~FileUploadHandler() override = default;

    /** Called from QML; iterates through fileUrls and uploads each one */
    Q_INVOKABLE void uploadFiles(const QStringList& fileUrls);

signals:
    /** Emits “Success” or “Error” per file back to QML */
    void uploadResult(const QString& title, const QString& message);

private:
    /** Orchestrates all steps for a single file. Returns new file_id or 0 on failure */
    uint64_t processSingleFile(const std::string& localPath);

    // ─── Step 1: Read “localPath” into a vector<uint8_t> ─────────────────────────
    std::vector<uint8_t> readFileBytes(const std::string& path);

    // ─── Step 2: Build and encrypt file content under FEK ────────────────────────
    Symmetric::Ciphertext encryptFileContent(
        const std::vector<uint8_t>& plaintext,
        const std::array<uint8_t, 32>& fek,
        std::array<uint8_t, 16>& outFileNonce
        );

    // ─── Step 3: Build metadata JSON (filename + size) ──────────────────────────
    std::string buildPlainMetadata(const std::string& filename, size_t filesize);

    // ─── Step 4: Encrypt metadata JSON under MEK ────────────────────────────────
    Symmetric::Ciphertext encryptMetadata(
        const std::string& metaPlain,
        const std::array<uint8_t, 32>& mek,
        std::array<uint8_t, 16>& outMetadataNonce
        );

    // ─── Helper: Base64-encode a byte buffer ────────────────────────────────────
    static std::string base64Encode(const std::vector<uint8_t>& buf);

    // ─── Helper: Sign “msg” via Ed25519, return base64(signature) ───────────────
    std::string signWithEd25519(const KeyBundle& kb, const std::vector<uint8_t>& msg);

    // ─── Helper: Sign “msg” via Dilithium, return base64(signature) ─────────────
    std::string signWithDilithium(const KeyBundle& kb, const std::vector<uint8_t>& msg);

private:
    ClientStore* store;
};
