#include "RegisterHandler.h"
#include <QDebug>
#include <QMetaObject>
#include "RegisterHandler.h"
#include "../utils/HandlerUtils.h"
#include <QMetaObject>
#include <nlohmann/json.hpp>
#include "../utils/networking/HttpResponse.h"
#include "../utils/networking/asiosslclient.h"

RegisterHandler::RegisterHandler(ClientStore *store, QObject *parent)
    : QObject(parent), store(store) {}

void RegisterHandler::registerUser(const QString &username,
                                   const QString &password,
                                   const QString &confirm)
{
    if (username.isEmpty() || password.isEmpty() || confirm.isEmpty()) {
        emit registerResult("Error", "All fields are required");
        return;
    }
    if (password != confirm) {
        emit registerResult("Error", "Passwords do not match");
        return;
    }

    // run background work off the UI thread
    HandlerUtils::runAsync([=] { doRegister(username, password); });
}

void RegisterHandler::doRegister(QString username, QString password)
{
    KeyBundle kb;

    nlohmann::json j;
    j["username"]   = username.toStdString();
    j["key_bundle"] = kb.toJsonPublic();
    std::string bodyString = j.dump();

    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/keyhandler/register",
        bodyString,
        { { "Content-Type", "application/json" } }
        );

    AsioSslClient httpClient;
    HttpResponse resp = httpClient.sendRequest(req);

    QString title, msg;
    if (resp.statusCode == 201) {
        try {
            store->setUserWithPassword(
                username.toStdString(),
                password.toStdString(),
                kb
                );
            title = "Success";
            msg   = "Registration successful – you are now logged in.";
        } catch (const std::exception &ex) {
            title = "Error";
            msg   = QString("Registration succeeded but saving credentials failed:\n%1")
                      .arg(ex.what());
        }
    } else {
        title = "Error";
        msg   = QString("Server replied %1: %2")
                  .arg(resp.statusCode)
                  .arg(QString::fromStdString(resp.body));
    }

    QMetaObject::invokeMethod(
        this,
        [this, title, msg]() { emit registerResult(title, msg); },
        Qt::QueuedConnection
        );
}






