#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include "LoginHandler.h"
#include "RegisterHandler.h"
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include <sodium.h>














static void cryptoSelfTest()
{
    if (sodium_init() < 0) qFatal("libsodium failed");

    const char *alg = "Kyber1024";               // any enabled alg name
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) qFatal("liboqs failed to init %s", alg);

    qDebug() << "PQ KEM in use:" << kem->method_name;
    OQS_KEM_free(kem);
}

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;

    // expose our two handlers
    LoginHandler    loginHandler;
    RegisterHandler registerHandler;
    engine.rootContext()->setContextProperty("loginHandler",    &loginHandler);
    engine.rootContext()->setContextProperty("registerHandler", &registerHandler);

    // load the single root QML
    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    cryptoSelfTest();
    return app.exec();
}


