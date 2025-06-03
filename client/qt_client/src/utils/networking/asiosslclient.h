#pragma once

#include "NetworkClient.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <string>

/**
 * A concrete NetworkClient that uses Boost.Asio + OpenSSL (via Boost.Asio’s SSL wrapper)
 * to establish a TLS connection, send a raw HTTP request, and parse the raw HTTP response.
 */
class AsioSslClient : public NetworkClient {
public:
    AsioSslClient();
    ~AsioSslClient() override;

    // Initialize the SSL context by loading the CA certificate(s)
    void init(const std::string& caCertPath) override;

    // Send an HTTP request over TLS, return a parsed HttpResponse.
    HttpResponse sendRequest(const std::string& host, int port, const HttpRequest&  request, int timeoutSeconds = DEFAULT_TIMEOUT) override;

private:
    // The Asio I/O context (event loop). For synchronous calls, operations block until completion.
    std::shared_ptr<boost::asio::io_context> ioContext_;

    // The SSL context (wraps OpenSSL's SSL_CTX). Configure certificates here.
    std::shared_ptr<boost::asio::ssl::context> sslContext_;

    // Resolver: given a hostname and service (port), returns a list of endpoints (IP + port).
    std::shared_ptr<boost::asio::ip::tcp::resolver> resolver_;

    // The TLS‐wrapped socket (combines a tcp::socket with an SSL layer).
    // We allocate this inside sendRequest() for each call.
    std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> sslStream_;

    // Delete copy constructor & assignment to avoid accidentally duplicating sockets/contexts.
    AsioSslClient(const AsioSslClient&) = delete;
    AsioSslClient& operator=(const AsioSslClient&) = delete;

    // Allow moving if needed.
    AsioSslClient(AsioSslClient&&) noexcept = default;
    AsioSslClient& operator=(AsioSslClient&&) noexcept = default;
};
