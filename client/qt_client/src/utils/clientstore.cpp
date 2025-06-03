// ClientStore.cpp

#include "ClientStore.h"

#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <QDebug>                // for qDebug()

using json = nlohmann::json;

ClientStore::ClientStore(const std::string& jsonPath)
    : m_path(jsonPath)
{
    qDebug() << "ClientStore::ClientStore() ▶ m_path =" << QString::fromStdString(m_path);

    // Ensure the parent directory exists. For example: C:/Users/<you>/AppData/Roaming/.ssshare/
    std::filesystem::path p(m_path);
    if (p.has_parent_path()) {
        std::error_code ec;
        qDebug() << "ClientStore ctor ▶ creating directories for:"
                 << QString::fromStdString(p.parent_path().string());
        std::filesystem::create_directories(p.parent_path(), ec);
        if (ec) {
            qDebug() << "ClientStore ctor ▶ FAILED to create directory"
                     << QString::fromStdString(p.parent_path().string())
                     << "– error:" << QString::fromStdString(ec.message());
        }
        else {
            qDebug() << "ClientStore ctor ▶ directory ready:"
                     << QString::fromStdString(p.parent_path().string());
        }
    }
}

ClientStore::~ClientStore() {
    qDebug() << "ClientStore::~ClientStore() ▶ saving before destruction";
    save();
}

void ClientStore::load() {
    std::lock_guard<std::mutex> locker(m_mutex);
    qDebug() << "ClientStore::load() ▶ entered";

    // If the file does not exist at all, simply return:
    if (!std::filesystem::exists(m_path)) {
        qDebug() << "ClientStore::load() ▶ file does not exist:" << QString::fromStdString(m_path);
        return;
    }

    // Check if it is zero bytes long; if so, treat it like "no data" and return:
    {
        std::error_code ec;
        auto fileSize = std::filesystem::file_size(m_path, ec);
        if (!ec) {
            qDebug() << "ClientStore::load() ▶ existing file size =" << fileSize << "bytes";
            if (fileSize == 0) {
                qDebug() << "ClientStore::load() ▶ zero‐length file, skipping parse";
                return;
            }
        } else {
            qDebug() << "ClientStore::load() ▶ could not query file size for"
                     << QString::fromStdString(m_path) << ":" << QString::fromStdString(ec.message());
        }
    }

    std::ifstream in(m_path);
    if (!in.good()) {
        qDebug() << "ClientStore::load() ▶ cannot open for reading:" << QString::fromStdString(m_path);
        return;
    }

    json j;
    try {
        in >> j;
        qDebug() << "ClientStore::load() ▶ JSON successfully read from"
                 << QString::fromStdString(m_path);
    }
    catch (const nlohmann::json::parse_error& ex) {
        qDebug() << "ClientStore::load() ▶ JSON parse error in"
                 << QString::fromStdString(m_path) << ":" << ex.what();
        return;
    }

    try {
        from_json(j);
        qDebug() << "ClientStore::load() ▶ from_json() succeeded";
    }
    catch (const std::exception& ex) {
        qDebug() << "ClientStore::load() ▶ from_json() threw exception:" << ex.what();
    }
}

void ClientStore::save() {
    std::lock_guard<std::mutex> locker(m_mutex);
    qDebug() << "ClientStore::save() ▶ entered; building JSON";

    // Now that we hold m_mutex, we can call to_json() without deadlocking.
    json j = to_json();

    qDebug() << "ClientStore::save() ▶ opening file for write (truncate):" << QString::fromStdString(m_path);
    std::ofstream out(m_path, std::ios::out | std::ios::trunc);
    if (!out.good()) {
        qDebug() << "ClientStore::save() ▶ cannot open for writing:" << QString::fromStdString(m_path);
        return;
    }

    out << j.dump(4) << std::endl;
    out.flush();
    if (!out.good()) {
        qDebug() << "ClientStore::save() ▶ write to"
                 << QString::fromStdString(m_path)
                 << "failed";
    } else {
        qDebug() << "ClientStore::save() ▶ wrote JSON to"
                 << QString::fromStdString(m_path);
    }
}

std::optional<ClientStore::UserInfo> ClientStore::getUser() const {
    std::lock_guard<std::mutex> locker(m_mutex);
    qDebug() << "ClientStore::getUser() ▶ returning user present?"
             << (m_user.has_value() ? "yes" : "no");
    return m_user;
}

void ClientStore::setUser(const UserInfo& user) {
    {
        std::lock_guard<std::mutex> locker(m_mutex);
        m_user = user;
        qDebug() << "ClientStore::setUser() ▶ m_user.username set to"
                 << QString::fromStdString(user.username);
    }
    qDebug() << "ClientStore::setUser() ▶ calling save() to:"
             << QString::fromStdString(m_path);
    save();
}

FileClientData* ClientStore::getFileData(uint64_t file_id) {
    std::lock_guard<std::mutex> locker(m_mutex);
    auto it = m_files.find(file_id);
    if (it == m_files.end()) {
        qDebug() << "ClientStore::getFileData() ▶ no entry for file_id =" << file_id;
        return nullptr;
    }
    qDebug() << "ClientStore::getFileData() ▶ found entry for file_id =" << file_id;
    return &it->second;
}

void ClientStore::upsertFileData(const FileClientData& fcd) {
    {
        std::lock_guard<std::mutex> locker(m_mutex);
        m_files[fcd.file_id] = fcd;
        qDebug() << "ClientStore::upsertFileData() ▶ stored FileClientData for"
                 << fcd.file_id;
    }
    save();
}

void ClientStore::removeFileData(uint64_t file_id) {
    {
        std::lock_guard<std::mutex> locker(m_mutex);
        if (m_files.erase(file_id)) {
            qDebug() << "ClientStore::removeFileData() ▶ erased entry for file_id =" << file_id;
        } else {
            qDebug() << "ClientStore::removeFileData() ▶ no entry to erase for file_id =" << file_id;
        }
    }
    save();
}

// ────────────────────────────────────────────────────────────────────────────

json ClientStore::to_json() const {
    // **Do not lock m_mutex again here**—we assume caller already holds it.
    qDebug() << "ClientStore::to_json() ▶ serializing to JSON";

    json j;

    // 1) If a user is present, serialize that first:
    if (m_user.has_value()) {
        const auto& u = *m_user;
        json uj;
        uj["username"] = u.username;
        uj["private_keybundle"] = u.keybundle.toJsonPrivate();
        uj["public_keybundle"]  = u.keybundle.toJsonPublic();
        j["user"] = std::move(uj);
        qDebug() << "ClientStore::to_json() ▶ included user:" << QString::fromStdString(u.username);
    } else {
        qDebug() << "ClientStore::to_json() ▶ no user to serialize";
    }

    // 2) Then write out any file‐metadata in an array:
    json arr = json::array();
    for (const auto& [fid, fcd] : m_files) {
        arr.push_back(fcd.to_json());
        qDebug() << "ClientStore::to_json() ▶ adding file_id =" << fid;
    }
    j["files"] = std::move(arr);
    qDebug() << "ClientStore::to_json() ▶ finished serializing files array with size"
             << static_cast<int>(j["files"].size());

    return j;
}

void ClientStore::from_json(const json& j) {
    // **Do not lock m_mutex here**—we assume caller already holds it (load() did).
    qDebug() << "ClientStore::from_json() ▶ entered";

    // Clear existing state:
    m_user.reset();
    m_files.clear();
    qDebug() << "ClientStore::from_json() ▶ cleared in‐memory state";

    // 1) Parse “user” key if present
    if (j.contains("user")) {
        const json& uj = j.at("user");
        UserInfo uinfo;
        uinfo.username = uj.at("username").get<std::string>();
        uinfo.keybundle = KeyBundle::fromJsonPrivate(uj.at("private_keybundle"));
        m_user = std::move(uinfo);
        qDebug() << "ClientStore::from_json() ▶ loaded user:"
                 << QString::fromStdString(m_user->username);
    } else {
        qDebug() << "ClientStore::from_json() ▶ no \"user\" key in JSON";
    }

    // 2) Parse “files” array if present
    if (j.contains("files")) {
        const auto& arr = j.at("files");
        qDebug() << "ClientStore::from_json() ▶ parsing \"files\" array of length"
                 << static_cast<int>(arr.size());
        for (const auto& fj : arr) {
            FileClientData fcd = FileClientData::from_json(fj);
            m_files[fcd.file_id] = std::move(fcd);
            qDebug() << "ClientStore::from_json() ▶ restored FileClientData for"
                     << fcd.file_id;
        }
    } else {
        qDebug() << "ClientStore::from_json() ▶ no \"files\" key in JSON";
    }
}
