#pragma once

#include <QObject>
#include <QString>
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
#include "../utils/handlerutils.h"
#include "../utils/NetworkAuthUtils.h"

#include <QStandardPaths>
#include <QDir>
#include <QMetaObject>
#include <QDebug>
#include <fstream>
#include <sstream>


class DownloadFileHandler : public QObject {
    Q_OBJECT

public:
    explicit DownloadFileHandler(ClientStore* store, QObject* parent = nullptr);
    ~DownloadFileHandler() override = default;

    /** Called from QML */
    Q_INVOKABLE void downloadFile(int fileId);

signals:
    /** Emits “Success” or “Error” after each download attempt */
    void downloadResult(const QString& title, const QString& message);

private:
    bool processSingleFile(int fileId);

    ClientStore* store;

    // Helper to pull another user’s public bundle:
    // POST /api/users/getBundle { username: "<ownerUsername>" }
    // returns { key_bundle: { … } }
    std::optional<KeyBundle> fetchPublicBundle(const std::string& ownerUsername) {
        // Build JSON body
        nlohmann::ordered_json jbody;
        jbody["username"] = ownerUsername;
        std::string bodyStr = jbody.dump();

        // We assume store->getUser() is valid, so we have our logged‐in key bundle
        auto maybeUser = store->getUser();
        if (!maybeUser.has_value()) {
            qWarning() << "[DownloadFileHandler] fetchPublicBundle: no logged‐in user";
            return std::nullopt;
        }
        const auto& userInfo = *maybeUser;
        const auto& myUsername = userInfo.username;
        const auto& myKeyBundle = userInfo.fullBundle;

        // Make dual‐signature headers
        auto headers = NetworkAuthUtils::makeAuthHeaders(
            myUsername,
            myKeyBundle,
            "POST",
            "/api/users/getBundle",
            bodyStr
            );

        HttpRequest req(
            HttpRequest::Method::POST,
            "/api/users/getBundle",
            bodyStr,
            headers
            );
        AsioHttpClient client;
        client.init("");
        HttpResponse resp = client.sendRequest(req);
        if (resp.statusCode != 200) {
            qWarning() << "[DownloadFileHandler] fetchPublicBundle: HTTP status =" << resp.statusCode;
            return std::nullopt;
        }

        // Parse JSON
        nlohmann::json respJson;
        try {
            respJson = nlohmann::json::parse(resp.body);
        } catch (const std::exception& ex) {
            qWarning() << "[DownloadFileHandler] fetchPublicBundle: JSON parse error:"
                       << ex.what();
            return std::nullopt;
        }

        if (!respJson.contains("key_bundle")) {
            qWarning() << "[DownloadFileHandler] fetchPublicBundle: missing key_bundle";
            return std::nullopt;
        }

        // key_bundle is already a JSON object with exactly { preQuantum:…, postQuantum:… }
        nlohmann::json kbJson = respJson.at("key_bundle");
        try {
            KeyBundle kb = KeyBundle::fromJsonPrivate(kbJson.dump());
            return kb;
        } catch (const std::exception& ex) {
            qWarning() << "[DownloadFileHandler] fetchPublicBundle: failed to parse KeyBundle:"
                       << ex.what();
            return std::nullopt;
        }
    }
};
