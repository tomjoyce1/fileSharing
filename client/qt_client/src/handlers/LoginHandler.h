#pragma once
#include <QObject>
#include <QString>

class LoginHandler : public QObject {
    Q_OBJECT
public:
    explicit LoginHandler(QObject *parent = nullptr);

    Q_INVOKABLE void validateLogin(const QString &username,
                                   const QString &password);

signals:
    void loginResult(const QString &title,
                     const QString &message);
};
