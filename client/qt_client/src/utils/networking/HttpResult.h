#pragma once

#include <map>
#include <string>
#include <system_error>

/**
 * HttpResult holds either a success (with statusCode + headers + body)
 * or a network‐level error (via errorCode).  On success, errorCode == 0.
 *
 * TODO: work this in later for better error messages on the client!
 */
struct HttpResult {
    std::error_code errorCode{};

    int statusCode = 0;

    std::map<std::string, std::string> headers;

    std::string body;

    std::string errorMessage;
};
