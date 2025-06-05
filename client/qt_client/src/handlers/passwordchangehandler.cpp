#include "PasswordChangeHandler.h"
#include "../utils/ClientStore.h"

#include <QMetaObject>
#include <QDebug>

/* ───────── ctor ───────── */
PasswordChangeHandler::PasswordChangeHandler(ClientStore* store,
                                             QObject* parent)
    : QObject(parent)
    , m_store(store)
{}

/* ───────── slot exposed to QML (now only two args) ───────── */
void PasswordChangeHandler::changePassword(const QString& newPwd,
                                           const QString& confirmPwd)
{
    /* ❶ GUI-thread sanity checks */
    if (newPwd.isEmpty() || confirmPwd.isEmpty()) {
        emit changeResult("Error", "All fields are required");
        return;
    }
    if (newPwd != confirmPwd) {
        emit changeResult("Error", "New passwords do not match");
        return;
    }

    /* ❷ heavy lifting in a worker thread */
    auto fut = QtConcurrent::run([=] { doChange(newPwd); });

    auto *watch = new QFutureWatcher<void>(this);
    connect(watch, &QFutureWatcher<void>::finished,
            watch, &QObject::deleteLater);
    watch->setFuture(fut);
}

/* ───────── background worker (only newPwd) ───────── */
void PasswordChangeHandler::doChange(const QString& newPwd)
{
    // We pass `""` as oldPassword because ClientStore already has the MEK in memory.
    std::string err;
    bool ok = m_store->changePassword(newPwd.toStdString(), err);

    QString title   = ok ? "Success" : "Error";
    QString message = ok
                          ? "Password changed successfully."
                          : (err.empty() ? "Password change failed."
                                         : QString::fromStdString(err));

    /* back to the UI thread */
    QMetaObject::invokeMethod(
        this,
        [this, title, message]() {
            emit changeResult(title, message);
        },
        Qt::QueuedConnection);
}
