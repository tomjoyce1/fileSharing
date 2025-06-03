#pragma once
#include <QObject>
#include <QString>
#include <nlohmann/json.hpp>
#include "../utils/networking/HttpRequest.h"
#include "../utils/networking/HttpResult.h"
#include "../utils/ClientStore.h"
#include "../utils/crypto/KeyBundle.h"
#include "../utils/HandlerUtils.h"
#include "../Config.h"

/**
 * The RegisterHandler class TODO describe
 *
 * Chris C++ Requirement:
 * - Call by Value
 */

class RegisterHandler : public QObject {
    Q_OBJECT
public:
    explicit RegisterHandler(ClientStore* store, QObject *parent = nullptr);

    /** Exposed to QML */
    Q_INVOKABLE void registerUser(const QString &username,
                                  const QString &password,
                                  const QString &confirm);

signals:
    /** Delivered to QML */
    void registerResult(const QString &title, const QString &message);

private:
    void doRegister(QString username, QString password); // runs in worker

    ClientStore* store;
    AsioHttpClient net_;
};
