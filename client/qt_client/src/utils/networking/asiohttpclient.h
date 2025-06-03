#pragma once

#include "NetworkClient.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "HttpResult.h"        // see below for definition
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <chrono>
#include "../../config.h"

/**
 * A callback signature for asyncSendRequest:
 *
 *   void myCallback(const HttpResult& result);
 *
 * The client will invoke this exactly once, either on success or on any failure.
 *
 * Chris C++ Requirements:
 * - Default Arguments
 * - Run-time (Virtual Functions and Dynamic Dispatch)
 * - std::unique_ptr
 * - std::shared_ptr
 */
using HttpCallback = void(*)(const HttpResult&);

class AsioHttpClient : public NetworkClient {
public:
    AsioHttpClient();
    ~AsioHttpClient() override;

    // For plain HTTP, init() is a no-op:
    void init(const std::string& /*caCertPath*/) override { /* no-op */ }

    /** Synchronous HTTP/1.1 over plain TCP (blocking). */
    HttpResponse sendRequest(
        const std::string& host,
        int                 port,
        const HttpRequest&  request,
        int                 timeoutSeconds = DEFAULT_TIMEOUT
        ) override;

    HttpResponse sendRequest(const HttpRequest&  request,
                             int timeoutSeconds = DEFAULT_TIMEOUT)
    {
        auto& cfg = Config::instance();
        return sendRequest(cfg.serverHost,
                           cfg.serverPort,
                           request,
                           timeoutSeconds);
    }


private:

    // Underlying Asio objects:
    std::shared_ptr<boost::asio::io_context>           ioContext_;
    std::shared_ptr<boost::asio::ip::tcp::resolver>     resolver_;
    std::unique_ptr<boost::asio::ip::tcp::socket>       socket_;
    std::unique_ptr<boost::asio::steady_timer>          timer_;

    // Disable copy/assignment
    AsioHttpClient(const AsioHttpClient&) = delete;
    AsioHttpClient& operator=(const AsioHttpClient&) = delete;
};
