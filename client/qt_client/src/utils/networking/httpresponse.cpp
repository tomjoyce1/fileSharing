#include "HttpResponse.h"
#include <cstring>
#include <cctype>

HttpResponse::HttpResponse() : statusCode(0)
{}

HttpResponse::HttpResponse(int code, const std::map<std::string, std::string>& hdrs, const std::string& b) : statusCode(code), headers(hdrs), body(b)
{}

/**
 *  Chris C++ Requirements:
 *  - Dynamic Memory Allocation using new and delete
 */
HttpResponse HttpResponse::fromRaw(const std::string& raw) {
    // Allocate a mutable character buffer on the heap
    char* buffer = new char[raw.size() + 1];
    std::memcpy(buffer, raw.c_str(), raw.size() + 1);  // include '\0'

    char* ptr = buffer;

    // Skip "HTTP/1.1 " (9 characters)
    ptr += 9;

    // Parse status code (digits)
    int code = 0;
    while (std::isdigit(static_cast<unsigned char>(*ptr))) {
        code = code * 10 + (*ptr - '0');
        ptr++;
    }

    // Skip until end of status line ("\r\n")
    while (!(*ptr == '\r' && *(ptr + 1) == '\n')) {
        ptr++;
    }
    ptr += 2;  // skip "\r\n"

    // Parse headers until a blank line
    std::map<std::string, std::string> hdrs;
    while (!(*ptr == '\r' && *(ptr + 1) == '\n')) {
        // Read header key
        std::string key;
        while (*ptr != ':') {
            key.push_back(*ptr);
            ptr++;
        }
        ptr += 2;  // skip ": "

        // Read header value
        std::string value;
        while (!(*ptr == '\r' && *(ptr + 1) == '\n')) {
            value.push_back(*ptr);
            ptr++;
        }
        ptr += 2;  // skip "\r\n"

        hdrs[key] = value;
    }

    // Skip the final "\r\n" (end of headers)
    ptr += 2;

    // The remainder is the body
    std::string bodyStr(ptr);

    delete[] buffer;  // free heap allocation
    return HttpResponse(code, hdrs, bodyStr);
}
