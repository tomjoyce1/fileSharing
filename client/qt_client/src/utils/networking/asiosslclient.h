#pragma once
#include "NetworkClient.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <string>

class AsioSslClient : public NetworkClient {
public:
    AsioSslClient();
    ~AsioSslClient() override;

    /**  Load a custom CA-bundle, or pass an empty string to use the system store. */
    void init(const std::string& caCertPath) override;

    /**  Synchronous HTTPS request (blocking). */
    HttpResponse sendRequest(const HttpRequest& request,
                             int timeoutSeconds = DEFAULT_TIMEOUT);

    HttpResponse sendRequest(const std::string& host,
                             int                port,
                             const HttpRequest& request,
                             int timeoutSeconds = DEFAULT_TIMEOUT) override;

private:
    std::shared_ptr<boost::asio::io_context>                   io_;
    std::shared_ptr<boost::asio::ssl::context>         sslCtx_;
    std::shared_ptr<boost::asio::ip::tcp::resolver>            resolver_;
    std::unique_ptr<boost::asio::ssl::stream<
        boost::asio::ip::tcp::socket>>                         stream_;

    static std::shared_ptr<boost::asio::ssl::context>          s_ctx_;
    static std::vector<boost::asio::ip::tcp::endpoint>         s_cached_eps_;
    static std::mutex                                          s_eps_mtx_;

    /** tiny helper that prints & returns a 500 HttpResponse in one line */
    static HttpResponse makeError(const std::string& why);
};
