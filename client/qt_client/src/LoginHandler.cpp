#include "LoginHandler.h"

LoginHandler::LoginHandler(QObject *parent)
    : QObject(parent)
{}

void LoginHandler::validateLogin(const QString &username,
                                 const QString &password)
{
    if (username.isEmpty() || password.isEmpty()) {
        emit loginResult("Error", "Please enter both username and password");
        return;
    }
    // stub: always succeed
    emit loginResult("Success", "Logged in!");
}
