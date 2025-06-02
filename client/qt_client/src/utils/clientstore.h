#pragma once

#include "crypto/FileClientData.h"
#include "crypto/KeyBundle.h"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <string>

/**
 * Holds “who am I?” (username + KeyBundle) and “which files?” (map file_id→FileClientData).
 *
 * On disk, this is a single JSON at ~/.ssshare/client_store.json.
 */
class ClientStore {
public:
    /**
     * Construct with the full path to the JSON store, e.g. "~/.ssshare/client_store.json".
     */
    explicit ClientStore(const std::string& jsonPath);
    ~ClientStore();

    /**
     * Load user + files from disk into memory.
     * If the file does not exist, this simply leaves everything empty.
     */
    void load();

    /**
     * Save current in‐memory state back to disk (overwrites).
     */
    void save();

    //──────────────────────────────────────────────────────────────────────────

    /**
     * UserInfo: holds username + KeyBundle (both private & public).
     */
    struct UserInfo {
        std::string        username;
        KeyBundle          keybundle;         // contains both public and private keys
    };

    /**
     * Returns the loaded UserInfo, or std::nullopt if none is set yet.
     */
    std::optional<UserInfo> getUser() const;

    /**
     * Overwrite the user (e.g. after register) and immediately save to disk.
     */
    void setUser(const UserInfo& user);

    //──────────────────────────────────────────────────────────────────────────

    /**
     * Return a pointer to FileClientData for the given file_id, or nullptr if missing.
     */
    FileClientData* getFileData(uint64_t file_id);

    /**
     * Insert or update a FileClientData entry (e.g. after upload).  Then save().
     */
    void upsertFileData(const FileClientData& fcd);

    /**
     * Remove a file_id (if you delete it) and save().
     */
    void removeFileData(uint64_t file_id);

private:
    std::string   m_path;   // e.g. "/home/alice/.ssshare/client_store.json"
     mutable std::mutex   m_mutex;

    // In‐memory copy:
    std::optional<UserInfo>                        m_user;   // empty if not registered
    std::unordered_map<uint64_t, FileClientData>   m_files;  // file_id → FileClientData

    /**
     * Helper: convert the in‐memory data to a nlohmann::json object.
     */
    nlohmann::json to_json() const;

    /**
     * Helper: given a JSON object, rebuild m_user and m_files.
     */
    void from_json(const nlohmann::json& j);
};
