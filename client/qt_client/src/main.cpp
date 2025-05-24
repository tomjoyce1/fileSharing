#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QDebug>
#include <QDir>
#include <QDirIterator>

int main(int argc, char *argv[])
{
    QQuickStyle::setStyle("Material");
    QGuiApplication app(argc, argv);

    // 1) List out every file in the “:/” resource root
    qDebug() << "Embedded QRC files:";
    QDirIterator it(":/", QDir::AllEntries | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        qDebug() << "   " << it.next();
    }

    // 2) Try loading the one we *think* is MainView
    QQmlApplicationEngine engine;
    QUrl url(QStringLiteral("qrc:/qml/MainView.qml"));
    qDebug() << "Attempting to load:" << url.toString();
    engine.load(url);

    if (engine.rootObjects().isEmpty()) {
        qCritical() << "Failed to load QML!" << url;
        return -1;
    }
    return app.exec();
}
