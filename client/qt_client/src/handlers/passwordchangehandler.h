#pragma once
#include <QObject>
#include <QString>
#include <QtConcurrent>
#include <QFutureWatcher>

class ClientStore;

/**
 * PasswordChangeHandler
 *
 * QML ➜ passwordHandler.changePassword(oldPwd, newPwd, confirm)
 *
 *  1. quick GUI-thread validation
 *  2. background thread:
 *       ClientStore::changePassword(oldPwd, newPwd)
 *  3. emits changeResult(title, message) back on the UI thread
 *
 *  No server round-trip – we only re-encrypt local material.
 */
class PasswordChangeHandler : public QObject
{
    Q_OBJECT
public:
    explicit PasswordChangeHandler(ClientStore* store,
                                   QObject* parent = nullptr);
    ~PasswordChangeHandler() override = default;

    Q_INVOKABLE void changePassword(const QString& newPassword,
                                    const QString& confirmPassword);

signals:
    void changeResult(const QString& title,
                      const QString& message);

private:
    void doChange(const QString& newPwd);

    ClientStore* m_store;
};
