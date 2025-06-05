#include "LoginHandler.h"
#include "../utils/ClientStore.h"
#include "../utils/HandlerUtils.h"
#include <QMetaObject>

LoginHandler::LoginHandler(ClientStore* store, QObject* parent)
    : QObject(parent), m_store(store) {}

void LoginHandler::validateLogin(const QString& username,
                                 const QString& password)
{
    if (username.isEmpty() || password.isEmpty()) {
        emit loginResult("Error", "Please enter both username and password");
        return;
    }

    // run background work off the UI thread
    HandlerUtils::runAsync([=] { doValidateLogin(username, password); });
}

void LoginHandler::doValidateLogin(const QString& username,
                                   const QString& password)
{
    std::string err;
    bool success = m_store->loginAndDecrypt(
        username.toStdString(),
        password.toStdString(),
        err);

    QString title = success ? "Success" : "Error";
    QString message;
    if (success) {
        message = "Login successful!";
    } else {
        message = err.empty() ? "Invalid username or password"
                              : QString::fromStdString(err);
    }

    QMetaObject::invokeMethod(
        this,
        [this, title, message]() { emit loginResult(title, message); },
        Qt::QueuedConnection);
}






