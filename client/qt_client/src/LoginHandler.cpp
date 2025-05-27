#include "LoginHandler.h"

LoginHandler::LoginHandler(QObject *parent) : QObject(parent) {}

void LoginHandler::validateLogin(const QString &username, const QString &password) {

    if (username == "user" && password == "pass") {
        emit loginResult("Success", "Login successful!");
    } else {
        emit loginResult("Error", "Invalid username or password.");
    }
}
