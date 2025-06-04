#include "LoginHandler.h"
#include "../utils/ClientStore.h"    // adjust the include path if necessary

#include <QMetaObject>
#include <QtConcurrent>
#include <QFutureWatcher>
#include <QDebug>

LoginHandler::LoginHandler(ClientStore* store, QObject* parent)
    : QObject(parent),
    m_store(store)
{
    // Assume ClientStore::load() was already called in main()
}

void LoginHandler::validateLogin(const QString& username,
                                 const QString& password)
{
    // Basic client‐side validation:
    if (username.isEmpty() || password.isEmpty()) {
        emit loginResult("Error", "Please enter both username and password");
        return;
    }

    // Run the “heavy lifting” (decrypting the ClientStore) off the UI thread:
    auto future = QtConcurrent::run([=] {
        doValidateLogin(username, password);
    });

    // Keep a watcher alive until the future finishes, then auto‐delete it:
    auto* watch = new QFutureWatcher<void>(this);
    connect(watch, &QFutureWatcher<void>::finished,
            watch, &QObject::deleteLater);
    watch->setFuture(future);
}

// NOTE: The signature here must match exactly what’s in LoginHandler.h
void LoginHandler::doValidateLogin(const QString& username,
                                   const QString& password)
{
    std::string err;
    bool success = m_store->loginAndDecrypt(
        username.toStdString(),
        password.toStdString(),
        err
        );

    QString title, message;
    if (success) {
        title = "Success";
        message = "Login successful!";
    } else {
        title = "Error";
        if (!err.empty()) {
            message = QString::fromStdString(err);
        } else {
            message = "Invalid username or password";
        }
    }

    if (success) {
            auto opt = m_store->getUser();
            if (opt) {
                    const auto& kb = opt->fullBundle;
                    qDebug() << "[DEBUG] ed25519PrivB64 length =" << QString::fromStdString(kb.getEd25519PrivateKeyBase64()).length();
                    qDebug() << "[DEBUG] x25519PrivB64 length =" << QString::fromStdString(kb.getX25519PrivateKeyBase64()).length();
                    qDebug() << "[DEBUG] dilithiumPrivB64 length =" << QString::fromStdString(kb.getDilithiumPrivateKeyBase64()).length();
                }
       }


    // Emit back on the main (UI) thread:
    QMetaObject::invokeMethod(
        this,
        [this, title, message]() {
            emit loginResult(title, message);
        },
        Qt::QueuedConnection
        );
}
