#pragma once
#include "HttpRequest.h"
#include "HttpResponse.h"
#include <string>

/**
 * The NetworkClient class
 *
 * Chris C++ Requirements:
 * - Function Overriding and Base Class Pointers (AsioHttpClient overrides)
 * - Run-time (Virtual Functions and Dynamic Dispatch)
 * - Pure Virtual Functions and Abstract Classes
 * - Virtual Destructors
 */
class NetworkClient {
public:
    virtual ~NetworkClient();

    /// Initialize the TLS/SSL context (e.g. load CA certificates, set up trust store).
    virtual void init(const std::string& caCertPath) = 0;

    /**
     * Send an HTTP request over TLS to the given host:port.
     *
     * @param host: the server hostname ("api.example.com")
     * @param port: the server port (443)
     * @param request: the HttpRequest object (method, path, headers, body)
     * @param timeoutSeconds: timeout in seconds
     * @return A parsed HttpResponse
     */
    virtual HttpResponse sendRequest(const std::string& host, int port, const HttpRequest& request, int timeoutSeconds = DEFAULT_TIMEOUT) = 0;

    /**
     * Overload with HttpRequest object
     */
    HttpResponse sendRequest(const HttpRequest& request);

    /**
     * Stores a default host and port so you don't have to specify a port and host on every call
     */
    void setHostPort(const std::string& host, int port);

protected:
    static constexpr int DEFAULT_TIMEOUT = 30;

    std::string host_;
    int port_;
};
