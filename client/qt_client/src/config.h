#pragma once
#include <string>
#include <chrono>

/**
 * AppConfig – holds global‐application settings.
 */
struct Config {
    // The one‐and‐only instance
    static Config& instance();

    std::string serverHost = "localhost";
    int serverPort = 3000;

    // Timeouts, in milliseconds
    std::chrono::milliseconds connectTimeoutMs = std::chrono::seconds(5);
    std::chrono::milliseconds readTimeoutMs = std::chrono::seconds(10);

private:
    Config();
    ~Config() = default;

    // no copying
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
};
