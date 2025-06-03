#pragma once
#include <string>
#include <map>

/**
 * Holds parts of a HTTP request (method, path, headers, body) and serializes itself into a raw string
 */
class HttpRequest {
public:
    enum class Method { GET, POST, PUT, DELETE };

    // Constructor with inline definition
    HttpRequest(Method m, const std::string& path, const std::string& body = "", const std::map<std::string, std::string>& headers = {});

    // Getters
    Method method() const;
    const std::string& path() const;
    const std::string& body() const;
    const std::map<std::string, std::string>& headers() const;

    // Add or overwrite a header
    void addHeader(const std::string& name, const std::string& value);

    // Serialize into raw HTTP/1.1 format
    std::string toString() const;

private:
    Method method_;
    std::string path_;
    std::string body_;
    std::map<std::string, std::string> headers_;
};
