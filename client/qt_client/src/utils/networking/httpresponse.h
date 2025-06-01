#pragma once
#include <string>
#include <map>

/**
 * Can parse a raw HTTP response string into a HttpResponse object
 */
class HttpResponse {
public:
    int statusCode;
    std::map<std::string, std::string> headers;
    std::string body;

    HttpResponse();
    HttpResponse(int code, const std::map<std::string, std::string>& hdrs, const std::string& b);

    // Parse a raw HTTP response into statusCode, headers, and body
    static HttpResponse fromRaw(const std::string& raw);
};
