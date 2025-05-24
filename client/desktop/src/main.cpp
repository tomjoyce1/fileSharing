// main.cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include "FileDialogHelper.h"

int main(int argc, char *argv[])
{
    QQuickStyle::setStyle("Material");
    QGuiApplication app(argc, argv);

    QQmlApplicationEngine engine;

    // 1) make our helper available to QML
    FileDialogHelper dlgHelper;
    engine.rootContext()->setContextProperty("FileDialogHelper", &dlgHelper);

    // 2) point QML imports
    engine.addImportPath("qrc:/qt/qml");

    // 3) load main QML
    engine.loadFromModule("EpicClient", "MainView");
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
