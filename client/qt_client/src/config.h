#pragma once
#include <string>
#include <chrono>

/**
 * AppConfig – holds global‐application settings.
 */
struct Config {
    // The one‐and‐only instance
    static Config& instance();

    std::string serverHost = "packetsniffers.gobbler.info";
    int serverPort = 443;
    std::string caBundle   = "cacert.pem";

    // Timeouts, in milliseconds
    std::chrono::milliseconds connectTimeoutMs = std::chrono::milliseconds(5000);
    std::chrono::milliseconds readTimeoutMs    = std::chrono::milliseconds(10000);

private:
    Config();
    ~Config() = default;

    // no copying
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
};
