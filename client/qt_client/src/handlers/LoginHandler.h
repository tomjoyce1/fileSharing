#pragma once
#include <QObject>
#include <QString>
#include <QtConcurrent>    // for QtConcurrent::run
#include <QFutureWatcher>  // for QFutureWatcher

class ClientStore;

class LoginHandler : public QObject {
    Q_OBJECT
public:
    explicit LoginHandler(ClientStore* store, QObject* parent = nullptr);

    // Exposed to QML:
    Q_INVOKABLE void validateLogin(const QString& username,
                                   const QString& password);

signals:
    // Emitted once the background ‐ threaded login attempt completes:
    void loginResult(const QString& title,
                     const QString& message);

private:
    // This does the “actual work” off the UI thread:
    void doValidateLogin(const QString& username,
                         const QString& password);

    ClientStore* m_store;
};
