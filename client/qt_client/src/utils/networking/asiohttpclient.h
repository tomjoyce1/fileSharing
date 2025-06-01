#pragma once

#include "NetworkClient.h"
#include <boost/asio.hpp>
#include <memory>
#include <string>

/**
 * AsioHttpClient
 *
 * A version of NetworkClient that does *plain HTTP* (no TLS).
 * This is the same as AsioSslClient but without the SSL layer.
 */
class AsioHttpClient : public NetworkClient {
public:
    AsioHttpClient();
    ~AsioHttpClient() override;

    // For plain HTTP, init() does nothing (no CA to load)
    void init(const std::string& /*caCertPath*/) override { /* no-op */ }

    // Send an HTTP request over plain TCP and return the parsed HttpResponse
    HttpResponse sendRequest(
        const std::string& host,
        int                 port,
        const HttpRequest&  request,
        int                 timeoutSeconds = DEFAULT_TIMEOUT
        ) override;

private:
    // I/O context for asynchronous operations (we do them synchronously in sendRequest())
    std::shared_ptr<boost::asio::io_context> ioContext_;

    // Resolver to turn "host:port" → endpoints (IP+port)
    std::shared_ptr<boost::asio::ip::tcp::resolver> resolver_;

    // The plain TCP socket we will wrap in each sendRequest() call
    // (We recreate it per‐request so it is fresh each time.)
    std::unique_ptr<boost::asio::ip::tcp::socket> socket_;

    // Delete copy/assignment so we don't accidentally duplicate sockets/contexts
    AsioHttpClient(const AsioHttpClient&) = delete;
    AsioHttpClient& operator=(const AsioHttpClient&) = delete;

    // Allow move if needed
    AsioHttpClient(AsioHttpClient&&) noexcept = default;
    AsioHttpClient& operator=(AsioHttpClient&&) noexcept = default;
};
