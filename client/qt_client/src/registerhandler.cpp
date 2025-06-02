#include "RegisterHandler.h"

#include <QFutureWatcher>
#include <QMetaObject>
#include <QDebug>
#include <QThread>
#include <QtConcurrent>

// Only needed if you manipulate JSON directly
#include <nlohmann/json.hpp>

/* ───────────────────────────────────────────────────────────── */

static inline QString tid()       // handy thread-id helper
{
    return QStringLiteral("[%1]")
        .arg(reinterpret_cast<quintptr>(QThread::currentThreadId()), 0, 16);
}

/* ───────────────────────────────────────────────────────────── */

RegisterHandler::RegisterHandler(ClientStore *store, QObject *parent)
    : QObject(parent),
    m_store(store)
{
    qDebug() << tid() << "RegisterHandler ctor – store =" << store;
}

/* ───────────────────────── registerUser ────────────────────── */

void RegisterHandler::registerUser(const QString &username,
                                   const QString &password,
                                   const QString &confirm)
{
    qDebug() << tid() << "registerUser() entered with:"
             << username << "(pwd len" << password.size() << ")";

    /* basic client-side validation */
    if (username.isEmpty() || password.isEmpty() || confirm.isEmpty()) {
        emit registerResult("Error", "All fields are required");
        qDebug() << tid() << "→ early-return: missing field(s)";
        return;
    }
    if (password != confirm) {
        emit registerResult("Error", "Passwords do not match");
        qDebug() << tid() << "→ early-return: passwords mismatch";
        return;
    }

    /* run the heavy work off the UI thread */
    auto fut = QtConcurrent::run([=] {
        qDebug() << tid() << "worker      → doRegister() starts";
        doRegister(username, password);
        qDebug() << tid() << "worker      → doRegister() ends";
    });

    /* keep this object alive until the worker finishes */
    auto *watch = new QFutureWatcher<void>(this);
    connect(watch,  &QFutureWatcher<void>::finished,
            watch,  &QObject::deleteLater);
    watch->setFuture(fut);
}

/* ───────────────────────── doRegister ─────────────────────── */

void RegisterHandler::doRegister(QString username, QString password)
{
    /* ❶  Create the KeyBundle (X25519, Ed25519, Dilithium-5) */
    KeyBundle kb;

    /* ❷  Build POST body */
    QByteArray body = QByteArrayLiteral("{\"username\":\"")
                      + username.toUtf8()
                      + "\",\"key_bundle\":"
                      + QByteArray::fromStdString(kb.toJson()) + '}';

    qDebug() << tid() << "doRegister(): JSON body size =" << body.size();

    /* ❸  Build HTTP request */
    HttpRequest req(HttpRequest::Method::POST,
                    "/api/keyhandler/register",
                    body.toStdString(),
                    { { "Host", kHost_.toStdString() },
                     { "Content-Type", "application/json" } });

    /* ❹  Send over plain HTTP */
    qDebug() << tid() << "doRegister(): sending HTTP POST …";
    HttpResponse resp = net_.sendRequest(kHost_.toStdString(), kPort_, req);

    qDebug() << tid() << "doRegister(): HTTP status =" << resp.statusCode;

    /* ❺  Interpret server response */
    QString title, msg;
    if (resp.statusCode == 201) {
        /* success – persist user locally */
        ClientStore::UserInfo u;
        u.username  = username.toStdString();
        u.keybundle = kb;
         qDebug() << "above setUser";
        if (m_store) m_store->setUser(u);
        qDebug() << "below setUser";

        title = "Success";
        msg   = "Registration successful – you are now logged in.";
    } else {
        title = "Error";
        msg   = QStringLiteral("Server replied %1: %2")
                  .arg(resp.statusCode)
                  .arg(QString::fromStdString(resp.body));
    }

    QMetaObject::invokeMethod(
        this,
        [this, title, msg]() {
            qDebug() << tid() << "UI-thread → emit registerResult:" << title << "|" << msg;
            emit registerResult(title, msg);
        },
        Qt::QueuedConnection
        );

}
