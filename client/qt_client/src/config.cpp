#include "Config.h"
#include <QDebug>

Config::Config() {
    qDebug() << "[Config] Using server:"
             << QString::fromStdString(serverHost)
             << ":" << serverPort
             << "| connectTimeout (ms):" << connectTimeoutMs.count()
             << "| readTimeout (ms):" << readTimeoutMs.count();
}

Config& Config::instance() {
    static Config cfg;
    return cfg;
}
