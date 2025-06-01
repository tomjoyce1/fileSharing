#include "RegisterHandler.h"
#include <QtConcurrent>            // <-- add QtConcurrent to QT += in .pro
#include <QFutureWatcher>
#include <QMetaObject>

RegisterHandler::RegisterHandler(QObject *parent)
    : QObject(parent)
{
    net_.init("");       // load CA bundle once
}

void RegisterHandler::registerUser(const QString &username,
                                   const QString &password,
                                   const QString &confirm)
{
    // basic client-side validation
    if (username.isEmpty() || password.isEmpty() || confirm.isEmpty()) {
        emit registerResult("Error", "All fields are required");
        return;
    }
    if (password != confirm) {
        emit registerResult("Error", "Passwords do not match");
        return;
    }

    // run the heavy work off the UI thread
    auto future = QtConcurrent::run([=]() { doRegister(username, password); });

    // ensure we keep this object alive until worker finishes
    auto *watch = new QFutureWatcher<void>(this);
    connect(watch, &QFutureWatcher<void>::finished,
            watch, &QObject::deleteLater);
    watch->setFuture(future);
}

void RegisterHandler::doRegister(QString username, QString password)
{
    /* ❶ Create the key bundle */
    KeyBundle kb;                     // generates X25519, Ed25519, Dilithium-5

    /* ❷ Build JSON body */
    const std::string body = std::string("{\"username\":\"")
                             + username.toStdString()
                             + "\",\"key_bundle\":"
                             + kb.toJson() + "}";

    /* ❸ Build HTTP request */
    HttpRequest req(HttpRequest::Method::POST,
                    "/api/keyhandler/register",
                    body,
                    { { "Host", kHost_.toStdString() } });   // Content-Type + Length auto-added

    /* ❹ Send */
    HttpResponse resp = net_.sendRequest(kHost_.toStdString(), kPort_, req);

    /* ❺ Interpret result */
    QString title, msg;
    if (resp.statusCode == 201) {
        title = "Success";
        msg   = "Registration successful";
    } else {
        title = "Error";
        msg   = QString("Server replied %1: %2")
                  .arg(resp.statusCode)
                  .arg(QString::fromStdString(resp.body));
    }

    // marshal back to UI thread
    QMetaObject::invokeMethod(this, [this,title,msg]{
            emit registerResult(title, msg);
        }, Qt::QueuedConnection);
}
