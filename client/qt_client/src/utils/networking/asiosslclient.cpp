#include "AsioSslClient.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <openssl/ssl.h> // For SSL_set_tlsext_host_name
#include <sstream>
#include <iostream>      // optional debug

AsioSslClient::AsioSslClient()
    : ioContext_(std::make_shared<boost::asio::io_context>()),
    sslContext_(std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12_client)),
    resolver_(std::make_shared<boost::asio::ip::tcp::resolver>(*ioContext_)),
    sslStream_(nullptr)
{
    // We require peer verification of the server certificate:
    sslContext_->set_verify_mode(boost::asio::ssl::verify_peer);
    // Do NOT load default verify paths here: caller must call init(caCertPath).
}

AsioSslClient::~AsioSslClient() {
    try {
        if (sslStream_ && sslStream_->next_layer().is_open()) {
            sslStream_->shutdown();
            sslStream_->lowest_layer().close();
        }
    } catch (...) {
        // Destructors must not throw
    }
}

void AsioSslClient::init(const std::string& caCertPath) {
    sslContext_->set_default_verify_paths();
}

HttpResponse AsioSslClient::sendRequest(
    const std::string& host,
    int                 port,
    const HttpRequest&  request,
    int                 timeoutSeconds
    ) {
    boost::system::error_code ec;

    // 1) Resolve hostname → endpoints
    auto endpoints = resolver_->resolve(host, std::to_string(port), ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "DNS resolution failed: " + ec.message());
    }

    // 2) (Re)create SSL stream wrapping a fresh tcp::socket
    sslStream_.reset(
        new boost::asio::ssl::stream<boost::asio::ip::tcp::socket>(*ioContext_, *sslContext_)
        );

    // 2a) Set SNI so server cert matches "host"
    if (!SSL_set_tlsext_host_name(sslStream_->native_handle(), host.c_str())) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "Failed to set SNI hostname");
    }

    // 3) Connect TCP
    boost::asio::connect(sslStream_->next_layer(), endpoints, ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "TCP connect failed: " + ec.message());
    }

    // 4) TLS handshake
    sslStream_->handshake(boost::asio::ssl::stream_base::client, ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "TLS handshake failed: " + ec.message());
    }

    // 5) Serialize HttpRequest → rawRequest
    std::string rawRequest = request.toString();

    // 6) Write to SSL stream
    boost::asio::write(*sslStream_, boost::asio::buffer(rawRequest), ec);
    if (ec) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "SSL write failed: " + ec.message());
    }

    // 7) Read until end of headers ("\r\n\r\n")
    boost::asio::streambuf responseBuf;
    boost::asio::read_until(*sslStream_, responseBuf, "\r\n\r\n", ec);
    if (ec && ec != boost::asio::error::eof) {
        std::map<std::string, std::string> emptyHeaders;
        return HttpResponse(500, emptyHeaders, "SSL read_until failed: " + ec.message());
    }

    // 8) Parse status line + headers
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

    // --- detect chunked -------------------------------------------------------
    bool chunked = false;
    auto teIter = responseHeaders.find("Transfer-Encoding");
    if (teIter != responseHeaders.end()) {
        std::string val = teIter->second;
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        chunked = val.find("chunked") != std::string::npos;
    }


    // 9) Content-Length if present
    std::size_t contentLength = 0;
    auto it = responseHeaders.find("Content-Length");
    if (it != responseHeaders.end()) {
        try {
            contentLength = std::stoul(it->second);
        } catch (...) {
            contentLength = 0;
        }
    }


    std::string body;

    if (chunked) {
        // --- very small chunked-decoder --------------------------------------
        while (true) {
            std::string sizeLine;
            std::getline(responseStream, sizeLine);       // "<hex>\r"
            if (!sizeLine.empty() && sizeLine.back() == '\r')
                sizeLine.pop_back();
            std::size_t chunkSize = std::stoul(sizeLine, nullptr, 16);
            if (chunkSize == 0) break;                    // last chunk

            std::vector<char> chunk(chunkSize);
            responseStream.read(chunk.data(), chunkSize);
            body.append(chunk.data(), chunkSize);

            responseStream.ignore(2);                     // skip trailing \r\n
        }
        // ignore optional trailer headers + final CRLF (already consumed)
    }
    else {
        if (contentLength > 0) {
            std::size_t alreadyInBuf = responseBuf.size();
            if (alreadyInBuf >= contentLength) {
                std::vector<char> tmp(contentLength);
                responseStream.read(tmp.data(), contentLength);
                body.assign(tmp.data(), contentLength);
            } else {
                std::vector<char> tmpIn(alreadyInBuf);
                responseStream.read(tmpIn.data(), alreadyInBuf);
                body.assign(tmpIn.data(), alreadyInBuf);

                std::size_t remaining = contentLength - alreadyInBuf;
                std::vector<char> tmpRest(remaining);
                boost::asio::read(*sslStream_, boost::asio::buffer(tmpRest), ec);
                if (ec && ec != boost::asio::error::eof) {
                    std::map<std::string, std::string> emptyHeaders;
                    return HttpResponse(500, emptyHeaders, "SSL read body failed: " + ec.message());
                }
                body.append(tmpRest.data(), tmpRest.size());
            }
        } else {
            // No Content-Length: read until EOF
            boost::system::error_code readEc;
            std::ostringstream oss;
            while (true) {
                char buf[1024];
                std::size_t n = sslStream_->read_some(boost::asio::buffer(buf), readEc);
                if (n > 0) {
                    oss.write(buf, static_cast<std::streamsize>(n));
                }
                if (readEc == boost::asio::error::eof) {
                    break;
                }
                if (readEc && readEc != boost::asio::error::would_block) {
                    std::map<std::string, std::string> emptyHeaders;
                    return HttpResponse(500, emptyHeaders, "SSL read (EOF) failed: " + readEc.message());
                }
            }
            body = oss.str();
        }
    }



    // 11) Reconstruct raw response for HttpResponse::fromRaw
    std::ostringstream fullResp;
    fullResp << statusLine << "\r\n";
    for (auto& kv : responseHeaders) {
        fullResp << kv.first << ": " << kv.second << "\r\n";
    }
    fullResp << "\r\n";
    fullResp << body;

    std::string rawResponse = fullResp.str();
    return HttpResponse::fromRaw(rawResponse);
}
