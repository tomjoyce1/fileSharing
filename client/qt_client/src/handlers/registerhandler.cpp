#include "RegisterHandler.h"
#include <QDebug>
#include <QMetaObject>
#include <nlohmann/json.hpp>
#include "../utils/networking/HttpResponse.h"

RegisterHandler::RegisterHandler(ClientStore *store, QObject *parent)
    : QObject(parent),
    store(store)
{
    qDebug() << "[RegisterHandler] Constructor - object created";
}

/* ───────────────────────── registerUser ────────────────────── */
void RegisterHandler::registerUser(const QString &username,
                                   const QString &password,
                                   const QString &confirm)
{
    qDebug().nospace()
        << "[RegisterHandler::registerUser] called with "
        << "username=\"" << username << "\"";

    /* basic client-side validation */
    if (username.isEmpty() || password.isEmpty() || confirm.isEmpty()) {
        qWarning() << "[RegisterHandler::registerUser] Validation failed: "
                      "One or more fields are empty";
        emit registerResult("Error", "All fields are required");
        return;
    }
    if (password != confirm) {
        qWarning() << "[RegisterHandler::registerUser] Validation failed: "
                      "Passwords do not match";
        emit registerResult("Error", "Passwords do not match");
        return;
    }

    /* run the heavy work off the UI thread */
    qDebug().nospace()
        << "[RegisterHandler::registerUser] Spawning worker thread to doRegister("
        << username << ")";
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
    qDebug().nospace()
        << "[RegisterHandler::doRegister] Starting registration for \""
        << username << "\"";

    /* ❶  Create the KeyBundle (X25519, Ed25519, Dilithium-5) */
    KeyBundle kb;
    qDebug().nospace()
        << "[RegisterHandler::doRegister] Generated new KeyBundle:"
        << " (X25519=" << kb.getX25519PublicRaw().size()
        << " bytes, Ed25519=" << kb.getEd25519PublicRaw().size()
        << " bytes, PQ=" << kb.getDilithiumPublicRaw().size() << " bytes)";

    /* ❷  Build JSON body using nlohmann::json */
    nlohmann::json j;
    j["username"]   = username.toStdString();
    j["key_bundle"] = kb.toJsonPublic();
    std::string bodyString = j.dump();
    qDebug().nospace()
        << "[RegisterHandler::doRegister] Built JSON body: "
        << QString::fromStdString(bodyString);

    /* ❸  Build HTTP request—but do NOT supply a “Host” header here.
            HttpRequest::toString() will auto-inject it from Config::instance(). */
    qDebug().nospace()
        << "[RegisterHandler::doRegister] Creating HttpRequest for "
        << "\"POST /api/keyhandler/register\"";

    HttpRequest req(
        HttpRequest::Method::POST,
        "/api/keyhandler/register",
        bodyString,
        {
            // Only supply content-type. “Host” will be added by HttpRequest::toString()
            { "Content-Type", "application/json" }
        }
        );

    qDebug().nospace()
        << "[RegisterHandler::doRegister] HttpRequest created. "
        << "Method=POST, Path=\"/api/keyhandler/register\", "
        << "Headers={Content-Type:application/json}";

    /* ❹  Send synchronously using the new overload.  No need to pass host/port. */
    AsioHttpClient httpClient;
    httpClient.init(""); // no TLS
    qDebug() << "[RegisterHandler::doRegister] Sending HTTP request...";
    HttpResponse resp = httpClient.sendRequest(req);

    qDebug().nospace()
        << "[RegisterHandler::doRegister] Received HTTP response: "
        << "StatusCode=" << resp.statusCode
        << ", Body=" << QString::fromStdString(resp.body);

    /* ❺  Interpret server response */
    QString title, msg;
    if (resp.statusCode == 201) {
        qDebug() << "[RegisterHandler::doRegister] Server returned 201 Created";

        // Server says “Created”.  Now store the new user in our encrypted ClientStore.
        try {
            qDebug().nospace()
                << "[RegisterHandler::doRegister] Calling store->setUserWithPassword("
                << username << ", <password omitted>, KeyBundle)";
            store->setUserWithPassword(
                username.toStdString(),
                password.toStdString(),
                kb  // “kb” holds both public+private keys in memory
                );
            qDebug() << "[RegisterHandler::doRegister] Local ClientStore updated successfully";

            title = "Success";
            msg   = "Registration successful – you are now logged in.";
        }
        catch (const std::exception& ex) {
            qWarning().nospace()
                << "[RegisterHandler::doRegister] ERROR saving to ClientStore: "
                << ex.what();
            title = "Error";
            msg   = QStringLiteral(
                      "Registration on server succeeded, but saving credentials locally failed:\n%1"
                      ).arg(ex.what());
        }
    }
    else {
        qWarning().nospace()
            << "[RegisterHandler::doRegister] Server returned non-201: "
            << resp.statusCode;
        title = "Error";
        msg   = QStringLiteral("Server replied %1: %2")
                  .arg(resp.statusCode)
                  .arg(QString::fromStdString(resp.body));
    }

    qDebug().nospace() << "[RegisterHandler::doRegister] Emitting registerResult("
                       << title << ", " << msg << ")";

    /* ❻  Emit result back on the UI thread */
    QMetaObject::invokeMethod(
        this,
        [this, title, msg]() {
            emit registerResult(title, msg);
        },
        Qt::QueuedConnection
        );
}
