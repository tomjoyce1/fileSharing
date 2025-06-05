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
#include "handlers/filedownloadhandler.h"
#include "handlers/passwordchangehandler.h"
#include "utils/ClientStore.h"
#include "utils/networking/asiosslclient.h"

static QString defaultStorePath() {
#ifdef Q_OS_WIN
    return QDir::homePath() + "/AppData/Roaming/.ssshare/client_store.json";
#else
    return QDir::homePath() + "/.ssshare/client_store.json";
#endif
}

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQuickStyle::setStyle("Material");  // Use Material style



    // 1) Load (or create) the ClientStore
    QString storeFile = defaultStorePath();
    ClientStore clientStore(storeFile.toStdString());
    clientStore.load();

    // 2) Create LoginHandler & RegisterHandler (they do NOT need fullBundle yet)
    LoginHandler    loginHandler(&clientStore);
    RegisterHandler registerHandler(&clientStore);
    PasswordChangeHandler pwdHandler(&clientStore);

    // 3) Expose only loginHandler & registerHandler to QML (for the login/register screens)
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("loginHandler",    &loginHandler);
    engine.rootContext()->setContextProperty("registerHandler", &registerHandler);
    engine.rootContext()->setContextProperty("passwordHandler", &pwdHandler);


    // 4) Placeholder pointers for upload/list; will create them only on successful login/register
    FileUploadHandler* uploadHandler   = nullptr;
    FileListHandler*   fileListHandler = nullptr;
    FileDownloadHandler* downloadHandler = nullptr;

    auto &cfg = Config::instance();
    QString absPem = QDir(QCoreApplication::applicationDirPath())
                         .filePath(QString::fromStdString(cfg.caBundle));
    cfg.caBundle = absPem.toStdString();

    AsioSslClient httpClient;
    httpClient.init(Config::instance().caBundle);

    // 5) Once login succeeds, construct + expose FileUploadHandler & FileListHandler
    QObject::connect(
        &loginHandler,
        &LoginHandler::loginResult,
        [&](QString title, QString message) {
            if (title == "Success") {
                // If we already had these from a previous session, delete them:
                if (uploadHandler)   { delete uploadHandler; }
                if (fileListHandler) { delete fileListHandler; }
                if (downloadHandler) { delete downloadHandler; }

                // Now clientStore.getUser()->fullBundle is valid
                uploadHandler   = new FileUploadHandler(&clientStore);
                fileListHandler = new FileListHandler(&clientStore);
                downloadHandler = new FileDownloadHandler(&clientStore);

                engine.rootContext()->setContextProperty("uploadHandler",   uploadHandler);
                engine.rootContext()->setContextProperty("fileListHandler", fileListHandler);
                engine.rootContext()->setContextProperty("downloadHandler", downloadHandler);

                fileListHandler->listAllFiles(1);
            }
            // if login fails, QML login dialog will show error (already implemented)
        }
        );

    // 6) Once registration succeeds, do the same
    QObject::connect(
        &registerHandler,
        &RegisterHandler::registerResult,
        [&](QString title, QString message) {
            if (title == "Success") {
                if (uploadHandler)   { delete uploadHandler; }
                if (fileListHandler) { delete fileListHandler; }
                if (downloadHandler) { delete downloadHandler; }


                uploadHandler   = new FileUploadHandler(&clientStore);
                fileListHandler = new FileListHandler(&clientStore);
                downloadHandler = new FileDownloadHandler(&clientStore);

                engine.rootContext()->setContextProperty("uploadHandler",   uploadHandler);
                engine.rootContext()->setContextProperty("fileListHandler", fileListHandler);
                engine.rootContext()->setContextProperty("downloadHandler", downloadHandler);

                fileListHandler->listAllFiles(1);
            }
        }
        );

    // 7) Finally load our root QML (which decides to show Login/Register vs. MainView)
    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
