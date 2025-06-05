// ClientStore.cpp

#include "ClientStore.h"

#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <QDebug>

#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include "crypto/symmetric.h"

using json = nlohmann::json;

/**
 * We use Symmetric::encrypt/decrypt (AES-256-CTR) instead of AES-GCM.
 * That means:
 *  • encrypt(plaintext, key) → { data=ciphertext, iv }  (iv is 16 bytes)
 *  • decrypt(ciphertext, key, iv) → plaintext
 *
 * No authentication tag is produced in CTR mode, so there's no tag to store.
 */

/**
 * A small Base64 wrapper around FileClientData's built-in routines.
 */
static std::string base64Encode(const std::vector<uint8_t>& v) {
    return FileClientData::base64_encode(v.data(), v.size());
}
static std::vector<uint8_t> base64Decode(const std::string& s) {
    return FileClientData::base64_decode(s);
}

// ──────────────────────────────────────────────────────────────────────────────
// Logging macro
// ──────────────────────────────────────────────────────────────────────────────
#ifndef CLS_LOG
#define CLS_LOG(tag)  qDebug().nospace() << "[ClientStore][" << tag << "] "
#endif


// ──────────────────────────────────────────────────────────────────────────────

ClientStore::ClientStore(const std::string& jsonPath)
    : m_path(jsonPath)
{
    CLS_LOG("ctor") << "m_path = " << QString::fromStdString(m_path);
    // Ensure parent directory exists (e.g. ~/.ssshare/)
    std::filesystem::path p(m_path);
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        if (ec) {
            CLS_LOG("ctor") << "FAILED to create directory "
                            << QString::fromStdString(p.parent_path().string())
                            << " – error: " << QString::fromStdString(ec.message());
        } else {
            CLS_LOG("ctor") << "Directory ready: "
                            << QString::fromStdString(p.parent_path().string());
        }
    }

    // Initialize libsodium (for Argon2id).  Will be a no-op if already initialized.
    if (sodium_init() < 0) {
        CLS_LOG("ctor") << "sodium_init() failed!";
    } else {
        CLS_LOG("ctor") << "sodium_init() OK";
    }
}

ClientStore::~ClientStore() {
    CLS_LOG("dtor") << "saving before destruction";
    save();
}

// ──────────────────────────────────────────────────────────────────────────────

void ClientStore::load() {
    std::lock_guard<std::mutex> locker(m_mutex);
    CLS_LOG("load") << "called";

    if (!std::filesystem::exists(m_path)) {
        CLS_LOG("load") << "file does not exist: " << QString::fromStdString(m_path);
        return;
    }

    {
        std::error_code ec;
        auto fileSize = std::filesystem::file_size(m_path, ec);
        if (!ec && fileSize == 0) {
            CLS_LOG("load") << "zero-length file, skipping parse";
            return;
        }
    }

    std::ifstream in(m_path);
    if (!in.good()) {
        CLS_LOG("load") << "cannot open for reading: " << QString::fromStdString(m_path);
        return;
    }

    json j;
    try {
        in >> j;
        CLS_LOG("load") << "JSON successfully read from " << QString::fromStdString(m_path);
    }
    catch (const json::parse_error& ex) {
        CLS_LOG("load") << "JSON parse error in " << QString::fromStdString(m_path)
                        << ": " << ex.what();
        return;
    }

    try {
        from_json(j);
        CLS_LOG("load") << "from_json() succeeded";
    }
    catch (const std::exception& ex) {
        CLS_LOG("load") << "from_json() threw exception: " << ex.what();
    }
}

void ClientStore::save() {
    CLS_LOG("save") << "called";
    std::lock_guard<std::mutex> locker(m_mutex);
    CLS_LOG("save") << "called; building JSON (files=" << m_files.size() << ")";

    json j = to_json();

    std::ofstream out(m_path, std::ios::out | std::ios::trunc);
    if (!out.good()) {
        CLS_LOG("save") << "cannot open for writing: " << QString::fromStdString(m_path);
        return;
    }

    out << j.dump(4) << std::endl;
    out.flush();
    if (!out.good()) {
        CLS_LOG("save") << "write to " << QString::fromStdString(m_path) << " failed";
    } else {
        CLS_LOG("save") << "wrote JSON to " << QString::fromStdString(m_path);
    }
}

// ──────────────────────────────────────────────────────────────────────────────

std::optional<ClientStore::UserInfo> ClientStore::getUser() const {
    std::lock_guard<std::mutex> locker(m_mutex);
    CLS_LOG("getUser") << "called; has_user=" << (m_user.has_value() ? "yes" : "no");
    return m_user;
}

void ClientStore::clearUser() {
    std::lock_guard<std::mutex> locker(m_mutex);
    CLS_LOG("clearUser") << "called";
    m_user.reset();
}

// ──────────────────────────────────────────────────────────────────────────────

FileClientData* ClientStore::getFileData(uint64_t file_id) {
    std::lock_guard<std::mutex> locker(m_mutex);
    auto it = m_files.find(file_id);
    if (it == m_files.end()) {
        CLS_LOG("getFileData") << "no entry for file_id=" << file_id;
        return nullptr;
    }
    CLS_LOG("getFileData") << "found entry for file_id=" << file_id;
    return &it->second;
}

void ClientStore::upsertFileData(const FileClientData& fcd) {
    {
        std::lock_guard<std::mutex> locker(m_mutex);
        m_files[fcd.file_id] = fcd;
        CLS_LOG("upsertFileData") << "stored FileClientData for file_id=" << fcd.file_id;
    }
    save();
}

void ClientStore::removeFileData(uint64_t file_id) {
    {
        std::lock_guard<std::mutex> locker(m_mutex);
        if (m_files.erase(file_id)) {
            CLS_LOG("removeFileData") << "erased entry for file_id=" << file_id;
        } else {
            CLS_LOG("removeFileData") << "no entry to erase for file_id=" << file_id;
        }
    }
    save();
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal JSON (de)serialization
// ──────────────────────────────────────────────────────────────────────────────

json ClientStore::to_json() const {
    // Assumes caller already holds m_mutex
    json j;
    if (m_user.has_value()) {
        const auto& u = *m_user;
        json uj;
        uj["username"]     = u.username;
        uj["salt"]         = base64Encode(u.salt);
        uj["master_nonce"] = base64Encode(u.masterNonce);
        uj["master_enc"]   = base64Encode(u.masterEnc);
        uj["priv_nonce"]   = base64Encode(u.privNonce);
        uj["priv_enc"]     = base64Encode(u.privEnc);

        // ── DEBUG: print out lengths BEFORE writing to disk ──
        CLS_LOG("to_json")
            << "Writing user fields => "
            << "saltB64.len="        << uj["salt"].get<std::string>().length()
            << ", masterNonceB64.len=" << uj["master_nonce"].get<std::string>().length()
            << ", masterEncB64.len="   << uj["master_enc"].get<std::string>().length()
            << ", privNonceB64.len="   << uj["priv_nonce"].get<std::string>().length()
            << ", privEncB64.len="     << uj["priv_enc"].get<std::string>().length();
        // You should see: saltB64.len=24, masterNonceB64.len=24,
        // masterEncB64.len>0, privNonceB64.len=24, privEncB64>1000 (or so).

        uj["public_keybundle"] = u.publicBundle.toJsonPublic();
        CLS_LOG("to_json") << "user move next! ";
        j["user"] = std::move(uj);
        CLS_LOG("to_json") << "serialized user: " << QString::fromStdString(u.username);
    } else {
        CLS_LOG("to_json") << "no user to serialize";
    }


    // Serialize files array
    json arr = json::array();
    for (const auto& [fid, fcd] : m_files) {
        arr.push_back(fcd.to_json());
    }
    j["files"] = std::move(arr);
    CLS_LOG("to_json") << "serialized files array, count=" << static_cast<int>(j["files"].size());

    return j;
}

void ClientStore::from_json(const json& j) {
    // Assumes caller already holds m_mutex
    m_user.reset();
    m_files.clear();
    CLS_LOG("from_json") << "entered";

    // 1) Parse “user” if present
    if (j.contains("user")) {
        const json& uj = j.at("user");
        UserInfo uinfo;
        uinfo.username = uj.at("username").get<std::string>();

        // Read and base64-decode salt, masterNonce, masterEnc, privNonce, privEnc
        uinfo.salt         = base64Decode( uj.at("salt").get<std::string>() );
        uinfo.masterNonce  = base64Decode( uj.at("master_nonce").get<std::string>() );
        uinfo.masterEnc    = base64Decode( uj.at("master_enc").get<std::string>() );
        uinfo.privNonce    = base64Decode( uj.at("priv_nonce").get<std::string>() );
        uinfo.privEnc      = base64Decode( uj.at("priv_enc").get<std::string>() );

        // Load public bundle
        uinfo.publicBundle = KeyBundle::fromJsonPublic( uj.at("public_keybundle").dump() );

        m_user = std::move(uinfo);
        CLS_LOG("from_json") << "loaded encrypted user: " << QString::fromStdString(m_user->username);
    }
    else {
        CLS_LOG("from_json") << "no “user” key in JSON";
    }

    // 2) Parse files array
    if (j.contains("files")) {
        const auto& arr = j.at("files");
        CLS_LOG("from_json") << "parsing files array, length=" << static_cast<int>(arr.size());
        for (const auto& fj : arr) {
            FileClientData fcd = FileClientData::from_json(fj);
            m_files[fcd.file_id] = std::move(fcd);
            CLS_LOG("from_json") << "restored FileClientData for file_id=" << fcd.file_id;
        }
    }
    else {
        CLS_LOG("from_json") << "no “files” key in JSON";
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Key-derivation & Randomness helpers
// ──────────────────────────────────────────────────────────────────────────────

bool ClientStore::derivePasswordKey(const std::string& password,
                                    const std::vector<uint8_t>& salt,
                                    std::vector<uint8_t>& outKey)
{
    CLS_LOG("argon2id") << "pwdLen=" << password.size()
                        << " saltLen=" << salt.size();
    // Argon2id with moderate ops/memory limits
    const size_t KEY_LEN = 32;
    if (outKey.size() != KEY_LEN) outKey.resize(KEY_LEN);

    bool ok = (0 == crypto_pwhash(
                   outKey.data(), KEY_LEN,
                   password.c_str(), password.size(),
                   salt.data(),
                   crypto_pwhash_OPSLIMIT_MODERATE,
                   crypto_pwhash_MEMLIMIT_MODERATE,
                   crypto_pwhash_ALG_ARGON2ID13
                   ));
    CLS_LOG("argon2id") << "done (success=" << (ok ? "yes" : "no") << ")";
    return ok;
}

bool ClientStore::randomBytes(size_t numBytes, std::vector<uint8_t>& out) {
    CLS_LOG("random") << "request " << numBytes << " byte(s)";
    out.resize(numBytes);
    bool ok = (RAND_bytes(out.data(), static_cast<int>(numBytes)) == 1);
    CLS_LOG("random") << "done (success=" << (ok ? "yes" : "no") << ")";
    return ok;
}

// ──────────────────────────────────────────────────────────────────────────────
// Registration: wrap a new KeyBundle under password (Argon2id → AES-CTR)
// ──────────────────────────────────────────────────────────────────────────────

void ClientStore::setUserWithPassword(const std::string& username,
                                      const std::string& password,
                                      const KeyBundle& fullKb)
{
    CLS_LOG("register") << "username=" << QString::fromStdString(username);

    // 1) Build up a new UserInfo "u" entirely, including random salt + MEK,
    //    then encrypt MEK under K_pwd, encrypt private bundle under MEK, etc.

    UserInfo u;
    u.username = username;

    // — generate salt (16 bytes) —
    if (!randomBytes(16, u.salt)) {
        throw std::runtime_error("Failed to generate Argon2 salt");
    }

    // — derive K_pwd via Argon2id(password, u.salt) —
    std::vector<uint8_t> K_pwd(32);
    if (!derivePasswordKey(password, u.salt, K_pwd)) {
        throw std::runtime_error("Argon2id KDF failed");
    }

    // — generate MEK (32 bytes) —
    if (!randomBytes(32, u.masterKey)) {
        throw std::runtime_error("Failed to generate MEK");
    }
    const std::vector<uint8_t> MEK = u.masterKey;  // copy for encryption

    // — encrypt MEK under K_pwd —
    {
        Symmetric::Ciphertext c = Symmetric::encrypt(MEK, K_pwd);
        CLS_LOG("encrypt") << "MEK len=" << MEK.size()
                           << " keyLen=" << K_pwd.size()
                           << " ivLen="  << c.iv.size();
        u.masterNonce = std::move(c.iv);
        u.masterEnc   = std::move(c.data);
    }

    // — now serialize the *private* KeyBundle JSON and encrypt under MEK —
    {
        std::string privJson   = fullKb.toJsonPrivate().dump();
        std::vector<uint8_t> privPlain(privJson.begin(), privJson.end());
        Symmetric::Ciphertext  c = Symmetric::encrypt(privPlain, MEK);
        CLS_LOG("encrypt") << "privPlain len=" << privPlain.size()
                           << " keyLen="     << MEK.size()
                           << " ivLen="      << c.iv.size();
        u.privNonce = std::move(c.iv);
        u.privEnc   = std::move(c.data);
    }

    // — keep the public KeyBundle in clear‐text form —
    u.publicBundle = fullKb;

    // — zero out K_pwd (best practice) —
    std::fill(K_pwd.begin(), K_pwd.end(), 0);

    // — store decrypted KeyBundle in memory for in‐RAM use —
    u.fullBundle = fullKb;

    // 2) Now that "u" is fully populated, move it into m_user *under lock*:
    {
        std::lock_guard<std::mutex> locker(m_mutex);
        m_user = std::move(u);
    } // <-- the lock is released here

    // 3) Finally, we can call save() without holding m_mutex:
    CLS_LOG("register") << "user stored in memory; calling save()";
    save();
}


// ──────────────────────────────────────────────────────────────────────────────
// Login: decrypt the stored MEK and private KeyBundle under (username, password)
// ──────────────────────────────────────────────────────────────────────────────

bool ClientStore::loginAndDecrypt(const std::string& username,
                                  const std::string& password,
                                  std::string& outError)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    CLS_LOG("login") << "username=" << QString::fromStdString(username);

    if (!m_user.has_value()) {
        outError = "No stored user found";
        CLS_LOG("login") << "no stored user";
        return false;
    }
    UserInfo& stored = *m_user;

    if (stored.username != username) {
        outError = "Username mismatch";
        CLS_LOG("login") << "username mismatch ("
                         << QString::fromStdString(stored.username) << " vs "
                         << QString::fromStdString(username) << ")";
        return false;
    }

    // 1) Derive K_pwd = Argon2id(password, salt)
    std::vector<uint8_t> K_pwd(32);
    if (!derivePasswordKey(password, stored.salt, K_pwd)) {
        outError = "Argon2id KDF failed";
        CLS_LOG("login") << "argon2id failed";
        return false;
    }

    // 2) Decrypt MEK ← AES-CTR(masterEnc, masterNonce, K_pwd)
    {
        Symmetric::Plaintext plainMEK = Symmetric::decrypt(
            stored.masterEnc,
            K_pwd,
            stored.masterNonce
            );
        CLS_LOG("decrypt") << "MEK cipher="   << stored.masterEnc.size()
                           << " keyLen="       << K_pwd.size()
                           << " ivLen="        << stored.masterNonce.size()
                           << " plainLen="     << plainMEK.data.size();
        std::vector<uint8_t> MEK = std::move(plainMEK.data);
        if (MEK.empty()) {
            outError = "Decrypting MEK failed (wrong password or corrupted data)";
            CLS_LOG("login") << "MEK decrypt failed";
            return false;
        }

        // 3) Decrypt private KeyBundle JSON ← AES-CTR(privEnc, privNonce, MEK)
        Symmetric::Plaintext privPlain = Symmetric::decrypt(
            stored.privEnc,
            MEK,
            stored.privNonce
            );
        CLS_LOG("decrypt") << "priv cipher="   << stored.privEnc.size()
                           << " keyLen="        << MEK.size()
                           << " ivLen="         << stored.privNonce.size()
                           << " plainLen="      << privPlain.data.size();
        std::vector<uint8_t> privJsonBytes = std::move(privPlain.data);
        if (privJsonBytes.empty()) {
            outError = "Decrypting private KeyBundle failed";
            CLS_LOG("login") << "private bundle decrypt failed";
            return false;
        }

        std::string privJson(reinterpret_cast<char*>(privJsonBytes.data()),
                             privJsonBytes.size());

        std::string privJsonStr(reinterpret_cast<char*>(privJsonBytes.data()),
                                privJsonBytes.size());
        qDebug().nospace() << "[ClientStore::loginAndDecrypt] Decrypted JSON ("
                           << privJsonStr.size() << " bytes):\n"
                           << privJsonStr;

        json j = json::parse(privJson);

        // 4) Reconstruct full KeyBundle
        KeyBundle fullKb = KeyBundle::fromJsonPrivate(j);

        // 5) Store decrypted MEK and fullBundle in memory
        stored.masterKey  = std::move(MEK);
        stored.fullBundle = std::move(fullKb);

        CLS_LOG("login") << "SUCCESS – user fully decrypted";
    }

    // 6) Clear K_pwd from memory
    std::fill(K_pwd.begin(), K_pwd.end(), 0);

    return true;
}

// ──────────────────────────────────────────────────────────────────────────────
// Change password: re-wrap MEK under new password
// ──────────────────────────────────────────────────────────────────────────────

bool ClientStore::changePassword(const std::string& oldPassword,
                                 const std::string& newPassword,
                                 std::string& outError)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    CLS_LOG("changePassword") << "called";

    if (!m_user.has_value()) {
        outError = "No user loaded";
        CLS_LOG("changePassword") << "no user loaded";
        return false;
    }
    UserInfo& stored = *m_user;

    // 1) Derive K_old = Argon2id(oldPassword, salt)
    std::vector<uint8_t> K_old(32);
    if (!derivePasswordKey(oldPassword, stored.salt, K_old)) {
        outError = "Old password KDF failed";
        CLS_LOG("changePassword") << "argon2id(old) failed";
        return false;
    }

    // 2) Decrypt MEK ← AES-CTR(masterEnc, masterNonce, K_old)
    Symmetric::Plaintext plainMEK = Symmetric::decrypt(
        stored.masterEnc,  // ciphertext
        K_old,             // decrypted key from old password
        stored.masterNonce // IV
        );
    CLS_LOG("decrypt") << "changePassword: MEK cipher=" << stored.masterEnc.size()
                       << " keyLen=" << K_old.size()
                       << " ivLen=" << stored.masterNonce.size()
                       << " plainLen=" << plainMEK.data.size();
    std::vector<uint8_t> MEK = std::move(plainMEK.data);
    if (MEK.empty()) {
        outError = "Old password is incorrect (unable to decrypt MEK)";
        CLS_LOG("changePassword") << "old password decrypt failed";
        return false;
    }

    // 3) Generate new salt (16 bytes), derive K_new = Argon2id(newPassword, newSalt)
    std::vector<uint8_t> newSalt;
    if (!randomBytes(16, newSalt)) {
        outError = "Failed to generate new salt";
        CLS_LOG("changePassword") << "random(newSalt) failed";
        return false;
    }
    std::vector<uint8_t> K_new(32);
    if (!derivePasswordKey(newPassword, newSalt, K_new)) {
        outError = "New password KDF failed";
        CLS_LOG("changePassword") << "argon2id(new) failed";
        return false;
    }

    // 4) Re-encrypt MEK under K_new → newMasterEnc, newMasterNonce
    Symmetric::Ciphertext c = Symmetric::encrypt(MEK, K_new);
    CLS_LOG("encrypt") << "changePassword: MEK len=" << MEK.size()
                       << " keyLen=" << K_new.size()
                       << " ivLen=" << c.iv.size();
    std::vector<uint8_t> newMasterNonce = std::move(c.iv);
    std::vector<uint8_t> newMasterEnc   = std::move(c.data);

    // 5) Update stored fields: salt, masterNonce, masterEnc
    stored.salt         = std::move(newSalt);
    stored.masterNonce  = std::move(newMasterNonce);
    stored.masterEnc    = std::move(newMasterEnc);

    // Clear K_old, K_new, MEK from memory
    std::fill(K_old.begin(), K_old.end(), 0);
    std::fill(K_new.begin(), K_new.end(), 0);
    std::fill(MEK.begin(), MEK.end(), 0);

    // 6) Persist changes to disk
    CLS_LOG("changePassword") << "persisting changes via save()";
    save();
    return true;
}

std::optional<KeyBundle> ClientStore::getPublicBundleForUsername(const std::string& username) const
{
    // TODO do this
    throw;
}
