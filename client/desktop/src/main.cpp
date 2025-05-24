#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>            // ← add this

int main(int argc, char *argv[])
{
    // force Material style in code:
    QQuickStyle::setStyle("Material");

    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    engine.loadFromModule("EpicClient","MainView");
    return app.exec();
}
