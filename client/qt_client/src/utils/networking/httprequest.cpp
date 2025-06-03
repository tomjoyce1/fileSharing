#include "HttpRequest.h"
#include <bits/stdc++.h>
#include "../../config.h"

HttpRequest::HttpRequest(Method m, const std::string& path, const std::string& body, const std::map<std::string, std::string>& headers) : method_(m), path_(path), body_(body), headers_(headers)
{}

// Getters
HttpRequest::Method HttpRequest::method() const {
    return method_;
}

const std::string& HttpRequest::path() const {
    return path_;
}

const std::string& HttpRequest::body() const {
    return body_;
}

const std::map<std::string, std::string>& HttpRequest::headers() const {
    return headers_;
}

void HttpRequest::addHeader(const std::string& name, const std::string& value) {
    this->headers_[name] = value;
}

// HttpRequest.cpp (replace toString() with change to auto‐inject Host if missing)
std::string HttpRequest::toString() const
{
    std::string methodStr;
    switch (method_) {
    case Method::GET:    methodStr = "GET";    break;
    case Method::POST:   methodStr = "POST";   break;
    case Method::PUT:    methodStr = "PUT";    break;
    case Method::DELETE: methodStr = "DELETE"; break;
    }

    std::string req = methodStr + " " + path_ + " HTTP/1.1\r\n";

    bool haveCT  = false;
    bool haveCL  = false;
    bool haveHost = false;

    // 1) user‐supplied headers
    for (const auto& kv : headers_) {
        std::string keyLower = kv.first;
        std::transform(keyLower.begin(), keyLower.end(), keyLower.begin(), ::tolower);
        if (keyLower == "content-type")   haveCT  = true;
        if (keyLower == "content-length") haveCL  = true;
        if (keyLower == "host")           haveHost = true;

        req += kv.first + ": " + kv.second + "\r\n";
    }

    // 2) Implicit Content-Type for JSON if body is nonempty
    if (!haveCT && !body_.empty()) {
        req += "Content-Type: application/json\r\n";
    }

    // 3) Implicit Content-Length if body is nonempty
    if (!haveCL && !body_.empty()) {
        req += "Content-Length: " + std::to_string(body_.size()) + "\r\n";
    }

    // 4) Implicit Host from Config if missing
    if (!haveHost) {
        auto& cfg = Config::instance();
        req += "Host: " + cfg.serverHost + ":" + std::to_string(cfg.serverPort) + "\r\n";
    }

    req += "\r\n";   // end headers
    req += body_;    // body (may be empty)
    return req;
}


