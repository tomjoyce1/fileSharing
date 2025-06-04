// main.cpp
#include <iostream>
#include <string>

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QDir>
#include <QDebug>

#include "handlers/LoginHandler.h"
#include "handlers/RegisterHandler.h"
#include "handlers/FileUploadHandler.h"
#include "handlers/FileListHandler.h"
#include "utils/ClientStore.h"

// -----------------------------------------------------------------------------
// Helper: where to keep client_store.json
static QString defaultStorePath() {
#ifdef Q_OS_WIN
    return QDir::homePath() + "/AppData/Roaming/.ssshare/client_store.json";
#else
    return QDir::homePath() + "/.ssshare/client_store.json";
#endif
}
// -----------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    // Use Material style in QML
    QQuickStyle::setStyle("Material");
    QQmlApplicationEngine engine;

    // 1) Create & load the ClientStore (may contain an encrypted keybundle on disk)
    QString storeFile = defaultStorePath();
    ClientStore clientStore(storeFile.toStdString());
    clientStore.load();

    // 2) Create the handlers that do NOT yet need fullBundle.
    //    We pass `&clientStore` so that they can register/login,
    //    but we do NOT expose upload/list until after successful login/register.
    LoginHandler    loginHandler(&clientStore);
    RegisterHandler registerHandler(&clientStore);

    // 3) Expose only loginHandler & registerHandler to QML for now.
    engine.rootContext()->setContextProperty("loginHandler",    &loginHandler);
    engine.rootContext()->setContextProperty("registerHandler", &registerHandler);

    // 4) We will create FileUploadHandler & FileListHandler later, once the user
    //    has either registered or logged in (so that clientStore.getUser()->fullBundle is non-empty).
    FileUploadHandler* uploadHandler   = nullptr;
    FileListHandler*   fileListHandler = nullptr;

    // 5) Connect to the LoginHandler::loginResult signal.  When login succeeds,
    //    clientStore.loginAndDecrypt(...) has already populated `fullBundle`.  We can now
    //    safely construct (or re-construct) our two “file‐operations” handlers and expose them.
    QObject::connect(
        &loginHandler,
        &LoginHandler::loginResult,
        [&](QString title, QString message){
            if (title == "Success") {
                // If we already had an uploadHandler/fileListHandler from a prior login, delete them:
                if (uploadHandler)   delete uploadHandler;
                if (fileListHandler) delete fileListHandler;

                // Now that loginAndDecrypt(...) has succeeded, clientStore.getUser()->fullBundle is valid.
                uploadHandler   = new FileUploadHandler(&clientStore);
                fileListHandler = new FileListHandler(&clientStore);

                // Expose to QML
                engine.rootContext()->setContextProperty("uploadHandler",   uploadHandler);
                engine.rootContext()->setContextProperty("fileListHandler", fileListHandler);
            }
            // If login failed, QML will show an error dialog (already implemented).
        }
        );

    // 6) Similarly, connect to the RegisterHandler::registerResult signal.  When registration
    //    succeeds, registerHandler has already called clientStore.setUserWithPassword(...),
    //    so `clientStore.getUser()->fullBundle` is valid immediately afterward.  We can now
    //    create/upload/list handlers and expose them, just as we do after login.
    QObject::connect(
        &registerHandler,
        &RegisterHandler::registerResult,
        [&](QString title, QString message){
            if (title == "Success") {
                // If we already had handlers from before, delete them:
                if (uploadHandler)   delete uploadHandler;
                if (fileListHandler) delete fileListHandler;

                // After a successful register, setUserWithPassword(...) ran, so the private bundle
                // is now stored in memory (and on disk encrypted).  We can create our handlers:
                uploadHandler   = new FileUploadHandler(&clientStore);
                fileListHandler = new FileListHandler(&clientStore);

                // Expose to QML
                engine.rootContext()->setContextProperty("uploadHandler",   uploadHandler);
                engine.rootContext()->setContextProperty("fileListHandler", fileListHandler);

                // Optionally, you might want to immediately switch the UI to “MainView”
                // or force a login‐to‐main transition from QML.  That is up to you.
            }
            // If registration failed, QML will show an error dialog (already implemented).
        }
        );

    // 7) Finally, load the root QML.  The Loader in Main.qml will show “Login” or “Register”
    //    first; only after a successful login/register do we expose uploadHandler/fileListHandler.
    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
