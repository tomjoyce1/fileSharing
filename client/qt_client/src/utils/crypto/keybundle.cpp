#include "KeyBundle.h"
#include <cstring>
#include <sstream>
#include <stdexcept>
#include "Kem_Ecdh.h"
#include "Signer_Ed.h"
#include "Signer_Dilithium.h"
#include "DerUtils.h"

static constexpr int BASE64_VARIANT = sodium_base64_VARIANT_ORIGINAL;


// Static helper: raw bytes → Base64 string
std::string KeyBundle::toBase64(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }
    // Compute required length of Base64 output
    size_t b64len = sodium_base64_encoded_len(data.size(), BASE64_VARIANT);

    std::string output;
    output.resize(b64len);

    // Write directly into string buffer
    sodium_bin2base64(
        &output[0],
        b64len,
        data.data(),
        data.size(),
        BASE64_VARIANT
        );

    if (!output.empty() && output.back() == '\0') {
        output.pop_back();
    }
    return output;
}

// Static helper: Base64 string → raw bytes
std::vector<uint8_t> KeyBundle::fromBase64(
    const std::string& b64,
    const std::string& nameForError
    ) {
    if (b64.empty()) {
        return {};
    }
    // Estimate upper bound on decoded length: floor(3/4 * Base64 length)
    size_t maxBinLen = (b64.size() * 3) / 4;
    std::vector<uint8_t> bin(maxBinLen);
    size_t binLen = 0;

    int ret = sodium_base642bin(
        bin.data(),
        maxBinLen,
        b64.c_str(),
        b64.size(),
        nullptr,
        &binLen,
        nullptr,
        BASE64_VARIANT
        );
    if (ret != 0) {
        throw std::invalid_argument(
            "KeyBundle::fromBase64(" + nameForError + "): invalid Base64"
            );
    }
    bin.resize(binLen);
    return bin;
}


KeyBundle::KeyBundle() {
    if (sodium_init() < 0) {
        throw std::runtime_error("KeyBundle::KeyBundle: sodium_init failed");
    }

    // X25519 KEM keypair
    Kem_Ecdh kemEcdh;
    kemEcdh.keygen();
    x25519Pub_ = kemEcdh.pub();

    // Ed25519 signature keypair
    Signer_Ed signerEd;
    signerEd.keygen();
    ed25519Pub_ = signerEd.pub();

    // Dilithium5 signature keypair
    Signer_Dilithium signerDilithium;
    signerDilithium.keygen();
    dilithiumPub_ = signerDilithium.pub();
}


KeyBundle::KeyBundle(
    const std::vector<uint8_t>& x25519Public,
    const std::vector<uint8_t>& ed25519Public,
    const std::vector<uint8_t>& dilithiumPublic
    ) {
    if (x25519Public.empty() || ed25519Public.empty() || dilithiumPublic.empty()) {
        throw std::invalid_argument(
            "KeyBundle::KeyBundle: public key vectors must not be empty"
            );
    }
    x25519Pub_    = x25519Public;
    ed25519Pub_   = ed25519Public;
    dilithiumPub_ = dilithiumPublic;
}


KeyBundle::KeyBundle(const KeyBundle& other)
    : x25519Pub_(other.x25519Pub_),
    ed25519Pub_(other.ed25519Pub_),
    dilithiumPub_(other.dilithiumPub_)
{}


KeyBundle& KeyBundle::operator=(const KeyBundle& other) {
    if (this != &other) {
        x25519Pub_    = other.x25519Pub_;
        ed25519Pub_   = other.ed25519Pub_;
        dilithiumPub_ = other.dilithiumPub_;
    }
    return *this;
}


KeyBundle::KeyBundle(KeyBundle&& other) noexcept
    : x25519Pub_(std::move(other.x25519Pub_)),
    ed25519Pub_(std::move(other.ed25519Pub_)),
    dilithiumPub_(std::move(other.dilithiumPub_))
{}


KeyBundle& KeyBundle::operator=(KeyBundle&& other) noexcept {
    if (this != &other) {
        x25519Pub_    = std::move(other.x25519Pub_);
        ed25519Pub_   = std::move(other.ed25519Pub_);
        dilithiumPub_ = std::move(other.dilithiumPub_);
    }
    return *this;
}


std::string KeyBundle::toJson() const
{
    // DER wrap → Base64
    const std::string kemB64 = toBase64( der::x25519(x25519Pub_) );
    const std::string edB64  = toBase64( der::ed25519(ed25519Pub_) );
    const std::string dilB64 = toBase64( dilithiumPub_ );      // raw already

    std::ostringstream oss;
    oss << R"({"preQuantum":{"identityKemPublicKey":")"       << kemB64
        << R"(","identitySigningPublicKey":")"                << edB64
        << R"("},"postQuantum":{"identitySigningPublicKey":")"<< dilB64
        << R"("}})";
    return oss.str();
}



KeyBundle KeyBundle::fromJson(const std::string& jsonStr) {
    // Helper lambda to extract the Base64 payload for a given key
    auto extractField = [&](const std::string& keyName) -> std::string {
        std::string pattern = "\"" + keyName + "\"";
        size_t pos = jsonStr.find(pattern);
        if (pos == std::string::npos) {
            throw std::invalid_argument(
                "KeyBundle::fromJson: missing field \"" + keyName + "\""
                );
        }
        // Skip past "keyName"
        pos = jsonStr.find(':', pos + pattern.size());
        if (pos == std::string::npos) {
            throw std::invalid_argument(
                "KeyBundle::fromJson: malformed JSON near \"" + keyName + "\""
                );
        }
        pos++;
        // Skip whitespace
        while (pos < jsonStr.size() && std::isspace((unsigned char)jsonStr[pos])) {
            pos++;
        }
        // Expect a double-quote
        if (pos >= jsonStr.size() || jsonStr[pos] != '"') {
            throw std::invalid_argument(
                "KeyBundle::fromJson: expected '\"' after field \"" + keyName + "\""
                );
        }
        pos++;
        // Read until next double-quote
        size_t start = pos;
        while (pos < jsonStr.size() && jsonStr[pos] != '"') {
            pos++;
        }
        if (pos >= jsonStr.size()) {
            throw std::invalid_argument(
                "KeyBundle::fromJson: unterminated string for \"" + keyName + "\""
                );
        }
        return jsonStr.substr(start, pos - start);
    };

    // Extract each Base64-encoded string
    std::string x25519_b64    = extractField("x25519");
    std::string ed25519_b64   = extractField("ed25519");
    std::string dilithium_b64 = extractField("dilithium");

    // Decode Base64 → raw bytes
    std::vector<uint8_t> x25519Bytes    = fromBase64(x25519_b64, "x25519");
    std::vector<uint8_t> ed25519Bytes   = fromBase64(ed25519_b64, "ed25519");
    std::vector<uint8_t> dilithiumBytes = fromBase64(dilithium_b64, "dilithium");

    // Construct KeyBundle from these raw public keys
    return KeyBundle(x25519Bytes, ed25519Bytes, dilithiumBytes);
}
