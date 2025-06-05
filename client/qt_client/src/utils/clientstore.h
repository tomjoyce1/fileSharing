#pragma once

#include "crypto/FileClientData.h"
#include "crypto/KeyBundle.h"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

/**
 * ClientStore manages:
 *  • “Who am I?” (username + KeyBundle public+private), stored on disk in encrypted form.
 *  • “Which files have I uploaded?” (map file_id → FileClientData), stored in clear.
 *
 * We separate authentication credentials from encryption credentials by using:
 *  1) A randomly-generated 32-byte MasterKey (MEK) that encrypts the private KeyBundle (AES-GCM).
 *  2) A password-derived key K_pwd = Argon2id(password, salt) that wraps (encrypts) the MEK (AES-GCM).
 *
 * At registration time, we:
 *  a) Generate 16-byte salt (for Argon2).
 *  b) Argon2id(password, salt) → 32-byte K_pwd.
 *  c) Generate random 32-byte MEK.
 *  d) Encrypt the private KeyBundle JSON under MEK → (privEnc, privNonce).
 *  e) Encrypt MEK under K_pwd → (masterEnc, masterNonce).
 *  f) Store on disk: { username, salt, masterEnc, masterNonce, privEnc, privNonce, publicKeyBundle }.
 *
 * At login time, we:
 *  a) Load those fields from disk.
 *  b) Argon2id(password, salt) → K_pwd
 *  c) Decrypt MEK ← AES-GCM(masterEnc, masterNonce, K_pwd).
 *  d) Decrypt private KeyBundle ← AES-GCM(privEnc, privNonce, MEK).
 *  e) Store in memory: full KeyBundle (public+private) and keep the encrypted fields for future password changes.
 *
 * When changing password, we:
 *  a) Argon2id(oldPass, salt) → K_old.
 *  b) Decrypt MEK ← AES-GCM(masterEnc, masterNonce, K_old).
 *  c) Generate newSalt (16 bytes), Argon2id(newPass, newSalt) → K_new.
 *  d) Re-encrypt MEK under K_new → (newMasterEnc, newMasterNonce).
 *  e) Overwrite (salt, masterEnc, masterNonce) in memory and on disk. Private-bundle fields stay the same.
 *
 * After any setUser or password change, ClientStore::save() will write the JSON to disk.
 *
 * Chris C++ Requirement:
 *  - Call by reference
 */

class ClientStore {
public:
    explicit ClientStore(const std::string& jsonPath);
    ~ClientStore();

    void load();

    /**
     * Save current in-memory state (encrypted user + all file metadata) to disk,
     * overwriting any existing file.
     */
    void save();

    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Represents all stored information about the current user.
     *
     * On disk, we save *only*:
     *   • username
     *   • salt (16 bytes, Argon2id salt)
     *   • masterNonce (16-byte IV for AES-CTR)
     *   • masterEnc   (AES-CTR ciphertext of the 32-byte MEK)
     *   • privNonce   (16-byte IV for AES-CTR)
     *   • privEnc     (AES-CTR ciphertext of private KeyBundle JSON)
     *   • publicKeyBundle (public-only JSON)
     *
     * In memory, after successful login, we additionally keep:
     *   • masterKey (the decrypted 32-byte MEK)
     *   • fullBundle (public+private KeyBundle)
     */
    struct UserInfo {
        std::string           username;

        // Public half of the KeyBundle (always stored in clear on disk)
        KeyBundle             publicBundle;

        // Encrypted MEK = AES-CTR(MEK, key = Argon2id(password, salt))
        std::vector<uint8_t>  salt;         // 16 bytes
        std::vector<uint8_t>  masterNonce;  // 16 bytes (IV used by AES-CTR)
        std::vector<uint8_t>  masterEnc;    // ciphertext of MEK

        // Encrypted PrivBundle = AES-CTR(privateKeyBundleJSON, key = MEK)
        std::vector<uint8_t>  privNonce;    // 16 bytes (IV for AES-CTR)
        std::vector<uint8_t>  privEnc;      // ciphertext of private KeyBundle JSON

        // — in-memory only, not serialized to disk —
        //       after login / decryption:
        std::vector<uint8_t>  masterKey;    // 32 bytes, decrypted MEK
        KeyBundle             fullBundle;   // public+private, decrypted
    };

    /**
     * Returns the loaded UserInfo if (and only if) someone has successfully logged in.
     */
    std::optional<UserInfo> getUser() const;

    /**
     * Set a newly registered user.  This function will:
     *   • Accept a fully-formed, decrypted `KeyBundle` (public+private).
     *   • Generate a random MEK, random salt, random nonces, wrap everything,
     *     and store in encrypted form in `m_user`.  Then call save().
     *
     * In other words, call this only *after* you have already done:
     *   • POST /api/keyhandler/register → server-side registration
     *   • Client-side KeyBundle kb = KeyBundle::generateNew();
     *   • Then call setUserWithPassword(username, password, kb).
     */
    void setUserWithPassword(const std::string& username,
                             const std::string& password,
                             const KeyBundle& fullKb);

    /**
     * Attempt to log in with (username, password).  Returns true if successful,
     * false otherwise.  On success, `m_user` is populated with all decrypted fields
     * (including `masterKey` and `fullBundle`), so that getUser() becomes non-empty.
     *
     * If login fails (wrong password or corruption), m_user remains unchanged
     * (and getUser() is still std::nullopt).
     */
    bool loginAndDecrypt(const std::string& username,
                         const std::string& password,
                         std::string& outError);

    /**
     * Change the user’s password.  Takes the old password & a new password.
     * Re-wraps the existing MEK under Argon2id(newPassword), and updates (salt, masterEnc, masterNonce).
     * Returns true on success, false on failure (e.g. wrong old password or corruption).
     *
     * After this call, save() is automatically invoked to persist the new salt+masterEnc.
     */
    bool changePassword(const std::string& newPassword,
                        std::string& outError);

    /**
     * Clears any in-memory user (logs out).  After this, getUser() → std::nullopt.
     * Does not delete the encrypted data on disk.
     */
    void clearUser();

    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Once a user is logged in, we store “which files” they own → FileClientData.
     * getFileData() returns a pointer to the FileClientData for a given file_id,
     * or nullptr if not found.
     */
    FileClientData* getFileData(uint64_t file_id);

    /**
     * Insert or update a FileClientData entry (e.g. after upload).  Then save().
     */
    void upsertFileData(const FileClientData& fcd);

    /**
     * Remove a file_id (e.g. if the user deletes a local record).  Then save().
     */
    void removeFileData(uint64_t file_id);

private:
    // Full path to the JSON file, e.g. "/home/alice/.ssshare/client_store.json"
    std::string             m_path;
    mutable std::mutex      m_mutex;

    // In-memory data:
    std::optional<UserInfo>                      m_user;   // populated only after login
    std::unordered_map<uint64_t, FileClientData> m_files;  // file_id → FileClientData

    // Helpers to (de)serialize to/from JSON.  Caller holds m_mutex before calling.
    nlohmann::json        to_json() const;
    void                  from_json(const nlohmann::json& j);

    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Internal helper: Argon2id(password, salt) → 32-byte key.
     * Returns true on success, false on failure.
     */
    static bool derivePasswordKey(const std::string& password,
                                  const std::vector<uint8_t>& salt,
                                  std::vector<uint8_t>& outKey);

    /**
     * Generate a vector of `numBytes` cryptographically secure random bytes.
     * Returns true on success.
     */
    static bool randomBytes(size_t numBytes, std::vector<uint8_t>& out);
};
