#include "NetworkClient.h"

NetworkClient::~NetworkClient() = default;

HttpResponse NetworkClient::sendRequest(const HttpRequest& request) {
    // Use the stored host_ and port_; default to DEFAULT_TIMEOUT
    return sendRequest(this->host_, this->port_, request, DEFAULT_TIMEOUT);
}

void NetworkClient::setHostPort(const std::string& host, int port) {
    this->host_ = host;
    this->port_ = port;
}
