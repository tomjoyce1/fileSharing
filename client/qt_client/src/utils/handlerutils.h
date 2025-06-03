#pragma once
#include <functional>
#include <nlohmann/json.hpp>
#include <QFutureWatcher>
#include <QtConcurrent>
#include "networking/AsioHttpClient.h"
#include "networking/HttpRequest.h"
#include "networking/HttpResponse.h"

// A raw function pointer which takes (const HttpResult&, void* userData)
using HttpResultCallback = void(*)(const HttpResult&, void*);
/**
 * HandlerUtils
 *
 * 1) runAsync(fn) ⇒ runs fn() in a QtConcurrent worker and auto‐deletes the QFutureWatcher when done.
 * 2) postJson(host, port, path, jsonBody) ⇒ serializes jsonBody, builds a POST HttpRequest, calls AsioHttpClient::sendRequest.
 *
 * Chris C++ Requirements:
 * - Inline Functions
 * - Function Pointers: Declaration and Usage, Passing Functions as Arguments
 */
namespace HandlerUtils {

    /**
         * Runs `task()` off the UI thread, then automatically deletes the watcher when finished.
         *
         * Usage:
         *   runAsync([=] {
         *      // ... do heavy work on background thread ...
         *   });
         */
    inline void runAsync(const std::function<void()>& task)
    {
        auto future = QtConcurrent::run(task);
        auto *watcher = new QFutureWatcher<void>();
        QObject::connect(watcher, &QFutureWatcher<void>::finished,
                         watcher, &QObject::deleteLater);
        watcher->setFuture(future);
    }

    inline void runAsyncStd(const std::function<void()>& task)
    {
        std::thread worker([task]() {
            task();
        });
        worker.detach();
    }

    /**
         * Sends a plain‐JSON POST to host:port/path.  Returns the raw HttpResponse.
         *
         * @param host      e.g. "localhost"
         * @param port      e.g. 3000
         * @param path      e.g. "/api/keyhandler/register"
         * @param jsonBody  any nlohmann::json object (will be serialized to text).
         */
    inline HttpResponse postJson(const std::string& host,
                                 int port,
                                 const std::string& path,
                                 const nlohmann::json& jsonBody)
    {
        std::string bodyString = jsonBody.dump();
        // Build an HttpRequest (automatically adds Content-Type & Content-Length if body non-empty)
        HttpRequest req(HttpRequest::Method::POST, path, bodyString, {
                                                                         { "Host", host + ":" + std::to_string(port) }
                                                                     });
        AsioHttpClient client;
        client.init(""); // no TLS
        return client.sendRequest(host, port, req);
    }

    /**
     * spawnRequest
     *
     * Runs a blocking AsioHttpClient::sendRequest(host, port, request) in a new thread,
     * then invokes `callback(HttpResult)` once complete.  Detaches the thread so it
     * does not block the caller.
     *
     * @param host       server hostname (e.g. "localhost")
     * @param port       server port (e.g. 3000)
     * @param request    an HttpRequest object containing method/path/headers/body
     * @param callback   a function pointer: void callback(const HttpResult&)
     */
    inline void spawnRequest(
        const std::string& host,
        int                port,
        const HttpRequest& request,
        HttpResultCallback userCallback,
        void*              userData
        ) {
        // We simply start a new std::thread to perform the blocking sendRequest() call.
        std::thread worker([=]() {
            AsioHttpClient client;
            client.init(""); // no TLS in this example

            HttpResponse resp = client.sendRequest(host, port, request);
            HttpResult    result;

            if (resp.statusCode >= 200 && resp.statusCode < 300) {
                // Success path: fill in statusCode, headers, body
                result.errorCode  = {}; // no error
                result.statusCode = resp.statusCode;
                result.headers    = std::move(resp.headers);
                result.body       = std::move(resp.body);
            } else {
                // Treat any non-2xx as an “error condition” (you can customize).
                result.errorCode    = std::make_error_code(std::errc::protocol_error);
                result.errorMessage = "HTTP error " + std::to_string(resp.statusCode) + ": " + resp.body;
            }

            // Finally invoke the raw function pointer, passing back the userData.
            if (userCallback) {
                userCallback(result, userData);
            }
        });

        // Detach so it runs independently; the callback must be prepared to be called on a background thread.
        worker.detach();
    }


}
