#include "HttpRequest.h"
#include <bits/stdc++.h>

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

// ─── HttpRequest::toString()  (replace the whole function) ────────────────
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

    // 1) user-supplied headers
    for (const auto& kv : headers_) {
        std::string keyLower = kv.first;
        std::transform(keyLower.begin(), keyLower.end(), keyLower.begin(), ::tolower);
        if (keyLower == "content-type")  haveCT = true;
        if (keyLower == "content-length") haveCL = true;

        req += kv.first + ": " + kv.second + "\r\n";
    }

    // 2) implicit Content-Type for requests that carry a body
    if (!haveCT && !body_.empty()) {
        req += "Content-Type: application/json\r\n";
    }

    // 3) Content-Length only when we actually have a body
    if (!haveCL && !body_.empty()) {
        req += "Content-Length: " + std::to_string(body_.size()) + "\r\n";
    }

    req += "\r\n";                // blank line to end headers
    req += body_;                 // body may be empty
    return req;
}

