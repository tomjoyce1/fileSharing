#include "RegisterHandler.h"
#include <QDebug>
#include <QMetaObject>
#include <nlohmann/json.hpp>
#include "../utils/networking/HttpResponse.h"
#include "../utils/networking/asiosslclient.h"

RegisterHandler::RegisterHandler(ClientStore *store, QObject *parent)
    : QObject(parent),
    store(store)
{}

/* ───────────────────────── registerUser ────────────────────── */

void RegisterHandler::registerUser(const QString &username,
                                   const QString &password,
                                   const QString &confirm)
{
    /* basic client-side validation */
    if (username.isEmpty() || password.isEmpty() || confirm.isEmpty()) {
        emit registerResult("Error", "All fields are required");
        return;
    }
    if (password != confirm) {
        emit registerResult("Error", "Passwords do not match");
        return;
    }

    /* run the heavy work off the UI thread */
    auto fut = QtConcurrent::run([=] {
        doRegister(username, password);
    });

    /* keep this object alive until the worker finishes */
    auto *watch = new QFutureWatcher<void>(this);
    connect(watch,  &QFutureWatcher<void>::finished,
            watch,  &QObject::deleteLater);
    watch->setFuture(fut);
}

/* ───────────────────────── doRegister ─────────────────────── */

void RegisterHandler::doRegister(QString username, QString password)
{
    /* ❶  Create the KeyBundle (X25519, Ed25519, Dilithium-5) */
    KeyBundle kb;

    /* ❷  Build JSON body using nlohmann::json */
    nlohmann::json j;
    j["username"]   = username.toStdString();
    j["key_bundle"] = kb.toJsonPublic();
    std::string bodyString = j.dump();

    /* ❸  Build HTTP request—but do NOT supply a “Host” header here.
            HttpRequest::toString() will auto-inject it from Config::instance(). */
    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/keyhandler/register",
        bodyString,
        {
            // Only supply content-type. “Host” will be added by HttpRequest::toString()
            { "Content-Type", "application/json" }
        }
        );

    /* ❹  Send synchronously using the new overload.  No need to pass host/port. */
    AsioSslClient httpClient; // 🔒 HTTPS

    // This version of sendRequest(...) pulls host/port from Config::instance():
    HttpResponse resp = httpClient.sendRequest(req);

    /* ❺  Interpret server response */
    QString title, msg;
    if (resp.statusCode == 201) {
        // Server says “Created”.  Now store the new user in our encrypted ClientStore.
        try {
            store->setUserWithPassword(
                username.toStdString(),
                password.toStdString(),
                kb                      // “kb” holds both public+private keys in memory
                );
            qDebug().nospace() << "[registerhandler] piss";
            title = "Success";
            msg   = "Registration successful – you are now logged in.";
        }
        catch (const std::exception& ex) {
            title = "Error";
            msg   = QStringLiteral(
                      "Registration on server succeeded, but saving credentials locally failed:\n%1"
                      ).arg(ex.what());
        }
    }
    else {
        title = "Error";
        msg   = QStringLiteral("Server replied %1: %2")
                  .arg(resp.statusCode)
                  .arg(QString::fromStdString(resp.body));
    }

    qDebug().nospace() << "[registerhandler] piss2";

    /* ❻  Emit result back on the UI thread */
    QMetaObject::invokeMethod(
        this,
        [this, title, msg]() {
            emit registerResult(title, msg);
        },
        Qt::QueuedConnection
        );
}
