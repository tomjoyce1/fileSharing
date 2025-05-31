#include "RegisterHandler.h"

RegisterHandler::RegisterHandler(QObject *parent)
    : QObject(parent)
{}

void RegisterHandler::registerUser(const QString &username,
                                   const QString &password,
                                   const QString &confirmPassword)
{
    if (username.isEmpty() || password.isEmpty() || confirmPassword.isEmpty()) {
        emit registerResult("Error", "All fields are required");
        return;
    }
    if (password != confirmPassword) {
        emit registerResult("Error", "Passwords do not match");
        return;
    }
    // stub: always succeed
    emit registerResult("Success", "Registration successful");
}
