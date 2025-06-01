#include "AsioHttpClient.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <sstream>
#include <iostream>

AsioHttpClient::AsioHttpClient()
    : ioContext_(std::make_shared<boost::asio::io_context>()),
    resolver_(std::make_shared<boost::asio::ip::tcp::resolver>(*ioContext_)),
    socket_(nullptr)
{
    // nothing to do in plain-HTTP init
}

AsioHttpClient::~AsioHttpClient() {
    try {
        if (socket_ && socket_->is_open()) {
            socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            socket_->close();
        }
    } catch (...) {
        // Destructors must not throw
    }
}

HttpResponse AsioHttpClient::sendRequest(
    const std::string& host,
    int                 port,
    const HttpRequest&  request,
    int                 /*timeoutSeconds – unused for plain TCP*/
    ) {
    boost::system::error_code ec;

    // 1) Resolve hostname → endpoints (e.g. "example.com", "80")
    auto endpoints = resolver_->resolve(host, std::to_string(port), ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(
            500,
            emptyHeaders,
            "DNS resolution failed: " + ec.message()
            );
    }

    // 2) Recreate a fresh TCP socket
    socket_.reset(new boost::asio::ip::tcp::socket(*ioContext_));

    // 3) Connect to the first available endpoint
    boost::asio::connect(*socket_, endpoints, ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(
            500,
            emptyHeaders,
            "TCP connect failed: " + ec.message()
            );
    }

    // 4) Build the raw HTTP request string and send it
    std::string rawRequest = request.toString();
    boost::asio::write(*socket_, boost::asio::buffer(rawRequest), ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "Write failed: " + ec.message());
    }

    // 5) Read until end of headers ("\r\n\r\n")
    boost::asio::streambuf responseBuf;
    boost::asio::read_until(*socket_, responseBuf, "\r\n\r\n", ec);
    if (ec && ec != boost::asio::error::eof) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "Read headers failed: " + ec.message());
    }

    // 6) Parse status line + headers
    std::istream responseStream(&responseBuf);
    std::string statusLine;
    std::getline(responseStream, statusLine); // e.g. "HTTP/1.1 200 OK"
    int statusCode = 0;
    {
        std::istringstream iss(statusLine);
        std::string httpVer;
        iss >> httpVer >> statusCode;
    }

    std::map<std::string, std::string> responseHeaders;
    std::string headerLine;
    while (std::getline(responseStream, headerLine) && headerLine != "\r") {
        auto sep = headerLine.find(':');
        if (sep != std::string::npos) {
            std::string key   = headerLine.substr(0, sep);
            std::string value = headerLine.substr(sep + 2);
            if (!value.empty() && value.back() == '\r') {
                value.pop_back();
            }
            responseHeaders[key] = value;
        }
    }

    // 7) Determine content length, or read chunked if needed
    bool chunked = false;
    {
        auto it = responseHeaders.find("Transfer-Encoding");
        if (it != responseHeaders.end()) {
            std::string val = it->second;
            std::transform(val.begin(), val.end(), val.begin(), ::tolower);
            if (val.find("chunked") != std::string::npos) {
                chunked = true;
            }
        }
    }

    std::size_t contentLength = 0;
    {
        auto it = responseHeaders.find("Content-Length");
        if (it != responseHeaders.end()) {
            try {
                contentLength = std::stoul(it->second);
            } catch (...) {
                contentLength = 0;
            }
        }
    }

    // 8) Read body
    std::string body;
    if (chunked) {
        // minimal chunked‐decoder
        while (true) {
            std::string sizeLine;
            std::getline(responseStream, sizeLine); // e.g. "1a3f\r"
            if (!sizeLine.empty() && sizeLine.back() == '\r')
                sizeLine.pop_back();

            std::size_t chunkSize = 0;
            try {
                chunkSize = std::stoul(sizeLine, nullptr, 16);
            } catch (...) {
                chunkSize = 0;
            }
            if (chunkSize == 0) {
                break; // last chunk
            }

            std::vector<char> chunkBuf(chunkSize);
            responseStream.read(chunkBuf.data(), chunkSize);
            body.append(chunkBuf.data(), chunkSize);

            // skip the "\r\n" at the end of each chunk
            responseStream.ignore(2);
        }
        // ignore any trailing headers
    }
    else {
        if (contentLength > 0) {
            std::size_t alreadyInBuf = responseBuf.size();
            if (alreadyInBuf >= contentLength) {
                std::vector<char> tmp(contentLength);
                responseStream.read(tmp.data(), contentLength);
                body.assign(tmp.data(), contentLength);
            } else {
                // read what’s already in the buffer
                std::vector<char> tmpIn(alreadyInBuf);
                responseStream.read(tmpIn.data(), alreadyInBuf);
                body.assign(tmpIn.data(), alreadyInBuf);

                // read the rest from the socket
                std::size_t remaining = contentLength - alreadyInBuf;
                std::vector<char> tmpRest(remaining);
                boost::asio::read(*socket_, boost::asio::buffer(tmpRest), ec);
                if (ec && ec != boost::asio::error::eof) {
                    std::map<std::string, std::string> emptyHeaders;
                    return HttpResponse(500, emptyHeaders, "Read body failed: " + ec.message());
                }
                body.append(tmpRest.data(), tmpRest.size());
            }
        } else {
            // no Content-Length: read until EOF
            boost::system::error_code readEc;
            std::ostringstream oss;
            while (true) {
                char buf[1024];
                std::size_t n = socket_->read_some(boost::asio::buffer(buf), readEc);
                if (n > 0) {
                    oss.write(buf, static_cast<std::streamsize>(n));
                }
                if (readEc == boost::asio::error::eof) {
                    break;
                }
                if (readEc && readEc != boost::asio::error::would_block) {
                    std::map<std::string, std::string> emptyHeaders;
                    return HttpResponse(500, emptyHeaders, "Read EOF failed: " + readEc.message());
                }
            }
            body = oss.str();
        }
    }

    // 9) Build raw response string so HttpResponse::fromRaw(...) can parse it again
    std::ostringstream fullResp;
    fullResp << statusLine << "\r\n";
    for (auto& kv : responseHeaders) {
        fullResp << kv.first << ": " << kv.second << "\r\n";
    }
    fullResp << "\r\n";
    fullResp << body;

    return HttpResponse::fromRaw(fullResp.str());
}
