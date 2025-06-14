#include "AsioSslClient.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <openssl/ssl.h>
#include <filesystem>
#include <sstream>
#include <QDebug>
#include <boost/asio/ssl/host_name_verification.hpp>
#include "../../config.h"

std::shared_ptr<boost::asio::ssl::context> AsioSslClient::s_ctx_{};
std::vector<boost::asio::ip::tcp::endpoint> AsioSslClient::s_cached_eps_{};
std::mutex AsioSslClient::s_eps_mtx_;



AsioSslClient::AsioSslClient()
    : io_(std::make_shared<boost::asio::io_context>()),
    resolver_(std::make_shared<boost::asio::ip::tcp::resolver>(*io_))
{
    if (!s_ctx_) {
        s_ctx_ = std::make_shared<boost::asio::ssl::context>(
            boost::asio::ssl::context::tls_client);
        s_ctx_->set_verify_mode(boost::asio::ssl::verify_peer);
    }
    sslCtx_ = s_ctx_;
}


AsioSslClient::~AsioSslClient()
{
    if (stream_ && stream_->next_layer().is_open()) {
        stream_->shutdown();
        stream_->next_layer().close();
    }
}



HttpResponse AsioSslClient::makeError(const std::string& why)
{
    std::map<std::string, std::string> hdrs;
    return HttpResponse(500, hdrs, why);
}



void AsioSslClient::init(const std::string& caPath)
{
    if (!caPath.empty())
        qDebug() << "[TLS INIT] loading CA bundle from"
                 << QString::fromStdString(caPath);
    else
        qDebug() << "[TLS INIT] using system default trust-store";

    if (!caPath.empty() && std::filesystem::exists(caPath)) {
        boost::system::error_code ec;
        sslCtx_->load_verify_file(caPath, ec);
        if (ec)
            throw std::runtime_error("load_verify_file: " + ec.message());
    } else {
        sslCtx_->set_default_verify_paths();
    }
}

HttpResponse AsioSslClient::sendRequest(const std::string& host,
                                        int                port,
                                        const HttpRequest& request,
                                        int timeoutSeconds)
{
    return sendRequest(request, timeoutSeconds);
}

HttpResponse AsioSslClient::sendRequest(const HttpRequest& request,
                                        int timeoutSeconds)
{
    const auto& cfg = Config::instance();
     std::string host = cfg.serverHost;
    int port =  cfg.serverPort;

    boost::system::error_code ec;

    // DNS
    std::vector<boost::asio::ip::tcp::endpoint> eps;
    {
        std::scoped_lock lk(s_eps_mtx_);
        if (s_cached_eps_.empty()) {
            auto results = resolver_->resolve(host, std::to_string(port), ec);
            if (ec) return makeError("DNS failed: " + ec.message());

                            s_cached_eps_.clear();
                    for (const auto& entry : results)
                               s_cached_eps_.push_back(entry.endpoint());
            }
        eps = s_cached_eps_;
    }

    // TLS
    stream_.reset(new boost::asio::ssl::stream<
                  boost::asio::ip::tcp::socket>(*io_, *sslCtx_));

    if (!SSL_set_tlsext_host_name(stream_->native_handle(), host.c_str()))
        return makeError("SNI set failed");

    // TCP connect
    boost::asio::connect(stream_->next_layer(), eps, ec);
    if (ec) {
        std::scoped_lock lk(s_eps_mtx_);
        s_cached_eps_.clear();
        return makeError("connect: " + ec.message());
    }

    // Handshake
    stream_->set_verify_callback(boost::asio::ssl::host_name_verification(host));    // ⭐ hostname ✔
    stream_->handshake(boost::asio::ssl::stream_base::client, ec);
    if (ec) return makeError("TLS handshake: " + ec.message());

    std::string rawReq = request.toString();
    boost::asio::write(*stream_, boost::asio::buffer(rawReq), ec);
    if (ec) return makeError("write: " + ec.message());

    boost::asio::streambuf buf;
    boost::asio::read_until(*stream_, buf, "\r\n\r\n", ec);
    if (ec && ec != boost::asio::error::eof)
        return makeError("read_until: " + ec.message());

    std::istream respStream(&buf);

    std::string statusLine; std::getline(respStream, statusLine);
    int status = 0; { std::istringstream ss(statusLine); std::string tmp; ss >> tmp >> status; }

    std::map<std::string,std::string> hdr;
    std::string line;
    while (std::getline(respStream,line) && line!="\r") {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0,pos);
        std::string v = line.substr(pos+2);         // skip ": "
        if (!v.empty() && v.back()=='\r') v.pop_back();
        hdr[k]=v;
    }

    // body (either chunked or Content-Length)
    bool chunked = false;
    if (auto it=hdr.find("Transfer-Encoding"); it!=hdr.end()) {
        std::string v = it->second; std::transform(v.begin(),v.end(),v.begin(),::tolower);
        chunked = v.find("chunked")!=std::string::npos;
    }
    std::size_t len = 0;
    if (auto it=hdr.find("Content-Length"); it!=hdr.end())
        len = std::stoul(it->second);

    std::string body;
    if (chunked) {
        while (true) {
            std::string sz; std::getline(respStream,sz); if (!sz.empty()&&sz.back()=='\r') sz.pop_back();
            std::size_t n = std::stoul(sz,nullptr,16); if (!n) { respStream.ignore(2); break; }
            std::vector<char> tmp(n); respStream.read(tmp.data(),n); body.append(tmp.data(),n); respStream.ignore(2);
        }
    } else {
        std::ostringstream oss; oss << respStream.rdbuf();
        while (body.size() + buf.size() < len) {         // read rest
            char tmp[4096]; std::size_t n = stream_->read_some(boost::asio::buffer(tmp), ec);
            if (!ec) oss.write(tmp, n); else break;
        }
        body = oss.str();
    }

    // build full raw response
    std::ostringstream raw;
    raw << statusLine << "\r\n";
    for (auto& kv:hdr) raw << kv.first << ": " << kv.second << "\r\n";
    raw << "\r\n" << body;

    qDebug() << "[HTTPS]" << QString::fromStdString(host)
             << status << "(" << rawReq.size() << "→" << body.size() << ")";

    return HttpResponse::fromRaw(raw.str());
}
