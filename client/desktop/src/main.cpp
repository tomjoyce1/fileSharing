#include <QGuiApplication>
#include <QQmlApplicationEngine>

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    // 1) Look in "./plugins" for *all* plugin types:
    QCoreApplication::addLibraryPath(app.applicationDirPath() + "/plugins");
    // 2) Still look in "./" so e.g.   "./imageformats" also works if present
    QCoreApplication::addLibraryPath(app.applicationDirPath());
    QQmlApplicationEngine engine;

    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed,
        &app, []() { qFatal("⚠️  QML failed to load — check paths and imports"); });

    engine.loadFromModule("EpicClient", "MainView");

    return app.exec();
}
