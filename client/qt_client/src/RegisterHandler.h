#pragma once
#include <QObject>
#include <QString>

#include "utils/networking/AsioSslClient.h"     // networking
#include "utils/crypto/KeyBundle.h"         // creates key bundle
#include "utils/networking/HttpRequest.h"       // serialise POST

class RegisterHandler : public QObject {
    Q_OBJECT
public:
    explicit RegisterHandler(QObject *parent = nullptr);

    /** Exposed to QML */
    Q_INVOKABLE void registerUser(const QString &username,
                                  const QString &password,
                                  const QString &confirm);

signals:
    /** Delivered to QML */
    void registerResult(const QString &title, const QString &message);

private:
    void doRegister(QString username, QString password); // runs in worker

    AsioSslClient net_;        // re-usable client (single-thread use)
    const QString kHost_  = "localhost";
    const int     kPort_  = 443;
    const QString kCACert_= "/etc/ssl/certs/ca-bundle.crt";
};
