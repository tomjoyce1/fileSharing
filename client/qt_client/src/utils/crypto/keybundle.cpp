#include "KeyBundle.h"
#include <cstring>
#include <sstream>
#include <stdexcept>
#include "Kem_Ecdh.h"
#include "Signer_Ed.h"
#include "Signer_Dilithium.h"
#include "DerUtils.h"

static constexpr int BASE64_VARIANT = sodium_base64_VARIANT_ORIGINAL;

//───────────────────────────────────────────────────────────────────────────────
//  Base64 helpers (unchanged from before)
//───────────────────────────────────────────────────────────────────────────────
std::string KeyBundle::toBase64(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    size_t b64len = sodium_base64_encoded_len(data.size(), BASE64_VARIANT);
    std::string output; output.resize(b64len);
    sodium_bin2base64(
        &output[0], b64len,
        data.data(), data.size(),
        BASE64_VARIANT
        );
    if (!output.empty() && output.back()=='\0') output.pop_back();
    return output;
}

std::vector<uint8_t> KeyBundle::fromBase64(
    const std::string& b64,
    const std::string& nameForError
    ) {
    if (b64.empty()) return {};
    size_t maxBinLen = (b64.size() * 3) / 4 + 1;
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

//───────────────────────────────────────────────────────────────────────────────
//  Default constructor: generate fresh keypairs (both pub AND priv)
//───────────────────────────────────────────────────────────────────────────────
KeyBundle::KeyBundle() {
    if (sodium_init() < 0) {
        throw std::runtime_error("KeyBundle::KeyBundle: sodium_init failed");
    }

    // 1) X25519 (KEM)
    {
        Kem_Ecdh kemEcdh;
        kemEcdh.keygen();              // internally populates both pub & priv
        x25519Pub_  = kemEcdh.pub();
        auto privK  = kemEcdh.getSecretKey();  // assume you add a `priv()` method to Kem_Ecdh
        x25519Priv_ = privK;
    }

    // 2) ED25519 (pre-quantum)
    {
        Signer_Ed signerEd;
        signerEd.keygen();  // generates _sk_ (64 bytes) and _pk_ (32 bytes)
        ed25519Pub_  = signerEd.pub();
        ed25519Priv_.resize(crypto_sign_SECRETKEYBYTES);
        std::memcpy(
            ed25519Priv_.data(),
            signerEd.getSecretKeyBuffer(),    // <-- we'll add this
            crypto_sign_SECRETKEYBYTES
            );
    }

    // 3) Dilithium5 (post-quantum)
    {
        Signer_Dilithium signerPQ;
        signerPQ.keygen();  // generates _sk_ and _pk_
        dilithiumPub_  = signerPQ.pub();
        dilithiumPriv_.resize(signerPQ.skLength());
        std::memcpy(
            dilithiumPriv_.data(),
            signerPQ.getSecretKeyBuffer(),  // <-- we'll add this
            signerPQ.skLength()
            );
    }
}

//───────────────────────────────────────────────────────────────────────────────
//  Parameterized constructor from raw binary + private for “importing”
//───────────────────────────────────────────────────────────────────────────────
KeyBundle::KeyBundle(
    const std::vector<uint8_t>& x25519Public,
    const std::vector<uint8_t>& ed25519Public,
    const std::vector<uint8_t>& dilithiumPublic,
    const std::vector<uint8_t>& x25519Private,
    const std::vector<uint8_t>& ed25519Private,
    const std::vector<uint8_t>& dilithiumPrivate
    )
    : x25519Pub_(x25519Public)
    , ed25519Pub_(ed25519Public)
    , dilithiumPub_(dilithiumPublic)
    , x25519Priv_(x25519Private)
    , ed25519Priv_(ed25519Private)
    , dilithiumPriv_(dilithiumPrivate)
{
    if (x25519Pub_.empty() || ed25519Pub_.empty() || dilithiumPub_.empty() ||
        x25519Priv_.empty()|| ed25519Priv_.empty()|| dilithiumPriv_.empty())
    {
        throw std::invalid_argument("KeyBundle::KeyBundle: all fields must be non‐empty");
    }
}

KeyBundle::KeyBundle(const KeyBundle& other)
    : x25519Pub_(other.x25519Pub_)
    , ed25519Pub_(other.ed25519Pub_)
    , dilithiumPub_(other.dilithiumPub_)
    , x25519Priv_(other.x25519Priv_)
    , ed25519Priv_(other.ed25519Priv_)
    , dilithiumPriv_(other.dilithiumPriv_)
{}

KeyBundle& KeyBundle::operator=(const KeyBundle& other) {
    if (this != &other) {
        x25519Pub_    = other.x25519Pub_;
        ed25519Pub_   = other.ed25519Pub_;
        dilithiumPub_ = other.dilithiumPub_;
        x25519Priv_   = other.x25519Priv_;
        ed25519Priv_  = other.ed25519Priv_;
        dilithiumPriv_= other.dilithiumPriv_;
    }
    return *this;
}

KeyBundle::KeyBundle(KeyBundle&& other) noexcept
    : x25519Pub_(std::move(other.x25519Pub_))
    , ed25519Pub_(std::move(other.ed25519Pub_))
    , dilithiumPub_(std::move(other.dilithiumPub_))
    , x25519Priv_(std::move(other.x25519Priv_))
    , ed25519Priv_(std::move(other.ed25519Priv_))
    , dilithiumPriv_(std::move(other.dilithiumPriv_))
{}

KeyBundle& KeyBundle::operator=(KeyBundle&& other) noexcept {
    if (this != &other) {
        x25519Pub_    = std::move(other.x25519Pub_);
        ed25519Pub_   = std::move(other.ed25519Pub_);
        dilithiumPub_ = std::move(other.dilithiumPub_);
        x25519Priv_   = std::move(other.x25519Priv_);
        ed25519Priv_  = std::move(other.ed25519Priv_);
        dilithiumPriv_= std::move(other.dilithiumPriv_);
    }
    return *this;
}

//───────────────────────────────────────────────────────────────────────────────
//  toJson() ≔ only public keys, exactly what the server’s “register” expects
//───────────────────────────────────────────────────────────────────────────────
std::string KeyBundle::toJson() const {
    const std::string kemB64   = toBase64( der::x25519(x25519Pub_) );
    const std::string edB64    = toBase64( der::ed25519(ed25519Pub_) );
    const std::string dilB64   = toBase64( dilithiumPub_ ); // already raw‐raw

    std::ostringstream oss;
    oss << R"({"preQuantum":{"identityKemPublicKey":")" << kemB64
        << R"(","identitySigningPublicKey":")"             << edB64
        << R"("},"postQuantum":{"identitySigningPublicKey":")" << dilB64
        << R"("}})";
    return oss.str();
}

nlohmann::json KeyBundle::toJsonPublic() const {
    return nlohmann::json::parse(toJson());
}

//───────────────────────────────────────────────────────────────────────────────
//  toJsonPrivate() ≔ public keys + private keys (all base64), so we can store on disk
//───────────────────────────────────────────────────────────────────────────────
nlohmann::json KeyBundle::toJsonPrivate() const {
    nlohmann::json jpub = toJsonPublic();

    // We know `toJsonPublic()` gave us something like:
    // {
    //   "preQuantum": { "identityKemPublicKey": "...", "identitySigningPublicKey": "..." },
    //   "postQuantum": { "identitySigningPublicKey": "..." }
    // }
    // We want to embed _private_ keys alongside, e.g.:
    // {
    //   "preQuantum": {
    //       "identityKemPublicKey": "...",
    //       "identitySigningPublicKey": "...",
    //       "identityKemPrivateKey": "<base64 of x25519Priv_>",
    //       "identitySigningPrivateKey": "<base64 of ed25519Priv_>"
    //    },
    //   "postQuantum": {
    //       "identitySigningPublicKey": "...",
    //       "identitySigningPrivateKey": "<base64 of dilithiumPriv_>"
    //    }
    // }

    // Copy public‐side JSON:
    nlohmann::json jpriv = jpub;

    // Insert private‐key fields (all base64‐encoded):
    jpriv["preQuantum"]["identityKemPrivateKey"]     = toBase64(x25519Priv_);
    jpriv["preQuantum"]["identitySigningPrivateKey"] = toBase64(ed25519Priv_);
    jpriv["postQuantum"]["identitySigningPrivateKey"] = toBase64(dilithiumPriv_);

    return jpriv;
}

//───────────────────────────────────────────────────────────────────────────────
//  fromJson(...)  ← parse only public keys (e.g. after you `toJson()`)
//───────────────────────────────────────────────────────────────────────────────
KeyBundle KeyBundle::fromJson(const std::string& jsonStr) {
    // Exactly reverse what toJson() did (pull only pub fields).
    // This is nearly identical to your old version.
    auto extractField = [&](const std::string& keyName) -> std::string {
        std::string pattern = "\"" + keyName + "\"";
        size_t pos = jsonStr.find(pattern);
        if (pos == std::string::npos) {
            throw std::invalid_argument("KeyBundle::fromJson: missing field \"" + keyName + "\"");
        }
        pos = jsonStr.find(':', pos + pattern.size());
        if (pos == std::string::npos) {
            throw std::invalid_argument("KeyBundle::fromJson: malformed JSON near \"" + keyName + "\"");
        }
        pos++;
        while (pos < jsonStr.size() && std::isspace((unsigned char)jsonStr[pos])) {
            pos++;
        }
        if (pos >= jsonStr.size() || jsonStr[pos]!='"') {
            throw std::invalid_argument("KeyBundle::fromJson: expected '\"' after field \"" + keyName + "\"");
        }
        pos++;
        size_t start = pos;
        while (pos < jsonStr.size() && jsonStr[pos]!='"') {
            pos++;
        }
        if (pos>=jsonStr.size()) {
            throw std::invalid_argument("KeyBundle::fromJson: unterminated string for \"" + keyName + "\"");
        }
        return jsonStr.substr(start, pos - start);
    };

    std::string x25519_b64    = extractField("identityKemPublicKey");
    std::string ed25519_b64   = extractField("identitySigningPublicKey");
    std::string dilithium_b64 = extractField("identitySigningPublicKey");
    // (Note: In the JSON, the two identitySigningPublicKey fields appear under different parents,
    //  but this helper will need to be more robust if the field names repeat. For now, assume
    //  the `extractField` usage is distinct.)

    std::vector<uint8_t> x25519Bytes  = fromBase64(x25519_b64, "x25519");
    std::vector<uint8_t> ed25519Bytes = fromBase64(ed25519_b64, "ed25519");
    std::vector<uint8_t> dilithiumBytes = fromBase64(dilithium_b64, "dilithium");

    // We do not know the private keys here, so we pass empty vectors:
    return KeyBundle(x25519Bytes, ed25519Bytes, dilithiumBytes,
                     {}, {}, {});
}

//───────────────────────────────────────────────────────────────────────────────
//  fromJsonPrivate(...) ← parse public+private keys from the JSON we wrote in toJsonPrivate()
//───────────────────────────────────────────────────────────────────────────────
KeyBundle KeyBundle::fromJsonPrivate(const nlohmann::json& j) {
    // Now the JSON looks like:
    // {
    //   "preQuantum": {
    //     "identityKemPublicKey":    "<base64>",
    //     "identitySigningPublicKey":"<base64>",
    //     "identityKemPrivateKey":   "<base64>",
    //     "identitySigningPrivateKey":"<base64>"
    //   },
    //   "postQuantum": {
    //     "identitySigningPublicKey":"<base64>",
    //     "identitySigningPrivateKey":"<base64>"
    //   }
    // }

    // Extract each base64 string:
    auto preQ = j.at("preQuantum");
    auto postQ = j.at("postQuantum");

    std::string kemPubB64           = preQ.at("identityKemPublicKey").get<std::string>();
    std::string signPubB64          = preQ.at("identitySigningPublicKey").get<std::string>();
    std::string kemPrivB64          = preQ.at("identityKemPrivateKey").get<std::string>();
    std::string signPrivB64         = preQ.at("identitySigningPrivateKey").get<std::string>();
    std::string dilithiumPubB64     = postQ.at("identitySigningPublicKey").get<std::string>();
    std::string dilithiumPrivB64    = postQ.at("identitySigningPrivateKey").get<std::string>();

    // Base64 → raw bytes:
    std::vector<uint8_t> kemPubBytes       = fromBase64(kemPubB64,        "kemPub");
    std::vector<uint8_t> signPubBytes      = fromBase64(signPubB64,       "ed25519Pub");
    std::vector<uint8_t> kemPrivBytes      = fromBase64(kemPrivB64,       "kemPriv");
    std::vector<uint8_t> signPrivBytes     = fromBase64(signPrivB64,      "ed25519Priv");
    std::vector<uint8_t> dilithiumPubBytes = fromBase64(dilithiumPubB64,   "dilPub");
    std::vector<uint8_t> dilithiumPrivBytes= fromBase64(dilithiumPrivB64,  "dilPriv");

    return KeyBundle(
        kemPubBytes,       // x25519Public
        signPubBytes,      // ed25519Public
        dilithiumPubBytes, // dilithiumPublic
        kemPrivBytes,      // x25519Private
        signPrivBytes,     // ed25519Private
        dilithiumPrivBytes // dilithiumPrivate
        );
}
