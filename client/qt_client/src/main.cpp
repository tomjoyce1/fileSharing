#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "LoginHandler.h"
#include "RegisterHandler.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    QQmlApplicationEngine engine;

    LoginHandler    loginHandler;
    RegisterHandler registerHandler;

    engine.rootContext()->setContextProperty("loginHandler",    &loginHandler);
    engine.rootContext()->setContextProperty("registerHandler", &registerHandler);

    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
