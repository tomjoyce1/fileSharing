// main.cpp
#include <iostream>
#include <string>


// Include Qt bits only if you want to integrate with QML.
// For a simple console‐only test, you don’t need QGuiApplication at all.
// But since your question asked for “in main create and run a testHttp() function”,
// we’ll keep a minimal main() that kicks off both tests in the console.

// If you prefer purely console, comment out all Qt includes and use:
// int main() { testHttp(); testHttps(); return 0; }

#include <QCoreApplication>
#include "utils/networking/AsioSslClient.h"
#include "utils/networking/HttpRequest.h"
#include "utils/networking/HttpResponse.h"
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "LoginHandler.h"
#include "RegisterHandler.h"


// ───────────────────────────── testHttps ─────────────────────────────
//
// Do an HTTPS GET to "www.example.com" on port 443, path "/".
//
void testHttps() {
    std::cout << "===== testHttps() → GET https://www.example.com/ =====\n";
    try {
        AsioSslClient sslClient;

        // If you want to trust the system CA store, pass empty string:
        sslClient.init("");

        // Alternatively, if you have a custom CA, pass that PEM path:
        // sslClient.init("C:/path/to/your/rootCA.pem");

        // Build a GET request for "/"
        HttpRequest req(
            HttpRequest::Method::GET,
            "/",
            "",
            { { "Host", "www.example.com" } }
            );

        HttpResponse resp = sslClient.sendRequest("www.example.com", 443, req);
        std::cout << "HTTPS/1.1 " << resp.statusCode << "\n";
        std::string truncated = resp.body.substr(0, std::min<size_t>(512, resp.body.size()));
        std::cout << "<BODY (first 512 chars)>\n" << truncated << "\n";
        if (resp.body.size() > 512) {
            std::cout << "...[truncated]...\n";
        }
    }
    catch (const std::exception& ex) {
        std::cout << "testHttps() threw: " << ex.what() << "\n";
    }
    std::cout << "===== end of testHttps() =====\n\n";
}

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    QQmlApplicationEngine engine;

    LoginHandler    loginHandler;
    RegisterHandler registerHandler;

    engine.rootContext()->setContextProperty("loginHandler",    &loginHandler);
    engine.rootContext()->setContextProperty("registerHandler", &registerHandler);

    testHttps();

    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
