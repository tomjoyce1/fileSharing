// KeyBundle.cpp

#include "KeyBundle.h"
#include <cstring>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <QDebug>               // For qDebug() and qWarning()
#include "DerUtils.h"           // der::x25519, der::ed25519, parseX25519Spki, parseEd25519Spki
#include "Kem_Ecdh.h"           // X25519 KEM keygen/pub/priv
#include "Signer_Ed.h"          // Ed25519 keygen/pub/priv
#include "Signer_Dilithium.h"   // Dilithium-5 keygen/pub/priv
#include <sodium.h>

static constexpr int BASE64_VARIANT = sodium_base64_VARIANT_ORIGINAL;

//───────────────────────────────────────────────────────────────────────────────
//  Base64 helpers
//───────────────────────────────────────────────────────────────────────────────
std::string KeyBundle::toBase64(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        qDebug() << "[KeyBundle::toBase64] Input data is empty → returning empty string.";
        return "";
    }
    qDebug().nospace()
        << "[KeyBundle::toBase64] Encoding " << data.size() << " raw bytes to Base64.";

    size_t needed = sodium_base64_encoded_len(data.size(), BASE64_VARIANT);
    std::string out;
    out.resize(needed);
    sodium_bin2base64(
        out.data(), needed,
        data.data(), data.size(),
        BASE64_VARIANT
        );
    if (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    qDebug().nospace()
        << "[KeyBundle::toBase64] Produced Base64 length=" << out.size();
    return out;
}

std::vector<uint8_t> KeyBundle::fromBase64(
    const std::string& b64,
    const std::string& nameForError
    ) {
    if (b64.empty()) {
        qDebug().nospace()
            << "[KeyBundle::fromBase64] Input Base64 for \"" << nameForError
            << "\" is empty → returning empty vector.";
        return {};
    }
    qDebug().nospace()
        << "[KeyBundle::fromBase64] Decoding Base64 for \"" << nameForError
        << "\", length=" << b64.size();

    size_t maxBinLen = (b64.size() * 3) / 4 + 16;
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
        qWarning().nospace()
            << "[KeyBundle::fromBase64] Failed to decode Base64 for \""
            << nameForError << "\"";
        throw std::invalid_argument(
            "KeyBundle::fromBase64(" + nameForError + "): invalid Base64"
            );
    }
    bin.resize(binLen);
    qDebug().nospace()
        << "[KeyBundle::fromBase64] Decoded \"" << nameForError
        << "\" into " << binLen << " raw bytes.";
    return bin;
}

//───────────────────────────────────────────────────────────────────────────────
//  Default constructor: generate fresh keypairs (raw)
//───────────────────────────────────────────────────────────────────────────────
KeyBundle::KeyBundle() {
    qDebug() << "[KeyBundle::KeyBundle] Entering default constructor.";
    if (sodium_init() < 0) {
        qWarning() << "[KeyBundle::KeyBundle] sodium_init() failed!";
        throw std::runtime_error("KeyBundle::KeyBundle: sodium_init failed");
    }

    // 1) X25519 (KEM)
    {
        qDebug() << "[KeyBundle::KeyBundle] Generating X25519 keypair...";
        Kem_Ecdh kem;
        kem.keygen();  // raw 32‐byte pub + raw 32‐byte priv
        x25519PubRaw_  = kem.pub();           // raw 32 bytes
        x25519PrivRaw_ = kem.getSecretKey();  // raw 32 bytes
        if (x25519PubRaw_.size() != 32 || x25519PrivRaw_.size() != 32) {
            qWarning() << "[KeyBundle::KeyBundle] X25519 key lengths incorrect:"
                       << x25519PubRaw_.size() << "/" << x25519PrivRaw_.size();
            throw std::runtime_error("X25519 keygen yielded wrong length");
        }
        qDebug().nospace()
            << "[KeyBundle::KeyBundle] X25519 generated (public=32 bytes, private=32 bytes).";
    }

    // 2) Ed25519 (pre-quantum signing)
    {
        qDebug() << "[KeyBundle::KeyBundle] Generating Ed25519 keypair...";
        Signer_Ed signerEd;
        signerEd.keygen(); // generates 64‐byte secret + 32‐byte public

        ed25519PubRaw_.assign(signerEd.pub().begin(), signerEd.pub().end());
        ed25519PrivRaw_.resize(crypto_sign_SECRETKEYBYTES);
        std::memcpy(
            ed25519PrivRaw_.data(),
            signerEd.getSecretKeyBuffer(),
            crypto_sign_SECRETKEYBYTES
            );
        if (ed25519PubRaw_.size() != 32 || ed25519PrivRaw_.size() != 64) {
            qWarning() << "[KeyBundle::KeyBundle] Ed25519 key lengths incorrect:"
                       << ed25519PubRaw_.size() << "/" << ed25519PrivRaw_.size();
            throw std::runtime_error("Ed25519 keygen yielded wrong length");
        }
        qDebug().nospace()
            << "[KeyBundle::KeyBundle] Ed25519 generated (public=32 bytes, private=64 bytes).";
    }

    // 3) Dilithium-5 (post-quantum signing)
    {
        qDebug() << "[KeyBundle::KeyBundle] Generating Dilithium-5 keypair (ML-DSA-87)...";
        Signer_Dilithium signerPQ;
        signerPQ.keygen();  // generates raw public + raw private

        dilithiumPubRaw_   = signerPQ.pub();
        dilithiumPrivRaw_.resize(signerPQ.skLength());
        std::memcpy(
            dilithiumPrivRaw_.data(),
            signerPQ.getSecretKeyBuffer(),
            signerPQ.skLength()
            );
        if (dilithiumPubRaw_.empty() || dilithiumPrivRaw_.empty()) {
            qWarning() << "[KeyBundle::KeyBundle] Dilithium-5 key lengths incorrect: "
                       << "public=" << dilithiumPubRaw_.size()
                       << ", private=" << dilithiumPrivRaw_.size();
            throw std::runtime_error("Dilithium-5 keygen failed");
        }
        qDebug().nospace()
            << "[KeyBundle::KeyBundle] Dilithium-5 generated (public="
            << dilithiumPubRaw_.size() << " bytes, private="
            << dilithiumPrivRaw_.size() << " bytes).";
    }

    qDebug() << "[KeyBundle::KeyBundle] Default constructor complete.";
}

//───────────────────────────────────────────────────────────────────────────────
//  Public-only constructor (raw public keys)
//───────────────────────────────────────────────────────────────────────────────
KeyBundle::KeyBundle(
    const std::vector<uint8_t>& x25519PublicRaw,
    const std::vector<uint8_t>& ed25519PublicRaw,
    const std::vector<uint8_t>& dilithiumPublicRaw
    )   : x25519PubRaw_(x25519PublicRaw),
    ed25519PubRaw_(ed25519PublicRaw),
    dilithiumPubRaw_(dilithiumPublicRaw)
{
    qDebug().nospace()
        << "[KeyBundle::KeyBundle(public)] Entering public-only ctor for public sizes: "
        << "X25519=" << x25519PubRaw_.size() << ", "
        << "Ed25519=" << ed25519PubRaw_.size() << ", "
        << "Dilithium=" << dilithiumPubRaw_.size();

    if (x25519PubRaw_.size() != 32 ||
        ed25519PubRaw_.size() != 32 ||
        dilithiumPubRaw_.empty())
    {
        qWarning().nospace()
            << "[KeyBundle::KeyBundle(public)] Invalid public key lengths: "
            << "X25519=" << x25519PubRaw_.size() << ", "
            << "Ed25519=" << ed25519PubRaw_.size() << ", "
            << "Dilithium=" << dilithiumPubRaw_.size();
        throw std::invalid_argument("KeyBundle(public): invalid public key lengths");
    }
    x25519PrivRaw_.clear();
    ed25519PrivRaw_.clear();
    dilithiumPrivRaw_.clear();

    qDebug() << "[KeyBundle::KeyBundle(public)] Public-only ctor complete.";
}

//───────────────────────────────────────────────────────────────────────────────
//  Full constructor (raw public + raw private)
//───────────────────────────────────────────────────────────────────────────────
KeyBundle::KeyBundle(
    const std::vector<uint8_t>& x25519PublicRaw,
    const std::vector<uint8_t>& ed25519PublicRaw,
    const std::vector<uint8_t>& dilithiumPublicRaw,
    const std::vector<uint8_t>& x25519PrivateRaw,
    const std::vector<uint8_t>& ed25519PrivateRaw,
    const std::vector<uint8_t>& dilithiumPrivateRaw
    )   : x25519PubRaw_(x25519PublicRaw),
    ed25519PubRaw_(ed25519PublicRaw),
    dilithiumPubRaw_(dilithiumPublicRaw),
    x25519PrivRaw_(x25519PrivateRaw),
    ed25519PrivRaw_(ed25519PrivateRaw),
    dilithiumPrivRaw_(dilithiumPrivateRaw)
{
    qDebug().nospace()
        << "[KeyBundle::KeyBundle(full)] Entering full ctor. Public sizes: "
        << "X25519=" << x25519PubRaw_.size() << ", "
        << "Ed25519=" << ed25519PubRaw_.size() << ", "
        << "Dilithium=" << dilithiumPubRaw_.size() << "; Private sizes: "
        << "X25519=" << x25519PrivRaw_.size() << ", "
        << "Ed25519=" << ed25519PrivRaw_.size() << ", "
        << "Dilithium=" << dilithiumPrivRaw_.size();

    if (x25519PubRaw_.size() != 32 ||
        ed25519PubRaw_.size() != 32 ||
        dilithiumPubRaw_.empty() ||
        x25519PrivRaw_.size() != 32 ||
        ed25519PrivRaw_.size() != crypto_sign_SECRETKEYBYTES ||
        dilithiumPrivRaw_.empty())
    {
        qWarning() << "[KeyBundle::KeyBundle(full)] One or more key lengths invalid:";
        qWarning().nospace() << "  x25519PubRaw=" << x25519PubRaw_.size()
                             << ", ed25519PubRaw=" << ed25519PubRaw_.size()
                             << ", dilithiumPubRaw=" << dilithiumPubRaw_.size();
        qWarning().nospace() << "  x25519PrivRaw=" << x25519PrivRaw_.size()
                             << ", ed25519PrivRaw=" << ed25519PrivRaw_.size()
                             << ", dilithiumPrivRaw=" << dilithiumPrivRaw_.size();

        throw std::invalid_argument("KeyBundle(full): invalid key lengths");
    }

    qDebug() << "[KeyBundle::KeyBundle(full)] Full ctor complete.";
}

KeyBundle::KeyBundle(const KeyBundle& other)
    : x25519PubRaw_(other.x25519PubRaw_),
    ed25519PubRaw_(other.ed25519PubRaw_),
    dilithiumPubRaw_(other.dilithiumPubRaw_),
    x25519PrivRaw_(other.x25519PrivRaw_),
    ed25519PrivRaw_(other.ed25519PrivRaw_),
    dilithiumPrivRaw_(other.dilithiumPrivRaw_)
{
    qDebug() << "[KeyBundle::KeyBundle(copy)] Copy constructor invoked.";
}

KeyBundle& KeyBundle::operator=(const KeyBundle& other) {
    if (this != &other) {
        qDebug() << "[KeyBundle::operator=] Copy assignment invoked.";
        x25519PubRaw_     = other.x25519PubRaw_;
        ed25519PubRaw_    = other.ed25519PubRaw_;
        dilithiumPubRaw_  = other.dilithiumPubRaw_;
        x25519PrivRaw_    = other.x25519PrivRaw_;
        ed25519PrivRaw_   = other.ed25519PrivRaw_;
        dilithiumPrivRaw_ = other.dilithiumPrivRaw_;
    }
    return *this;
}

KeyBundle::KeyBundle(KeyBundle&& other) noexcept
    : x25519PubRaw_(std::move(other.x25519PubRaw_)),
    ed25519PubRaw_(std::move(other.ed25519PubRaw_)),
    dilithiumPubRaw_(std::move(other.dilithiumPubRaw_)),
    x25519PrivRaw_(std::move(other.x25519PrivRaw_)),
    ed25519PrivRaw_(std::move(other.ed25519PrivRaw_)),
    dilithiumPrivRaw_(std::move(other.dilithiumPrivRaw_))
{
    qDebug() << "[KeyBundle::KeyBundle(move)] Move constructor invoked.";
}

KeyBundle& KeyBundle::operator=(KeyBundle&& other) noexcept {
    if (this != &other) {
        qDebug() << "[KeyBundle::operator=(move)] Move assignment invoked.";
        x25519PubRaw_     = std::move(other.x25519PubRaw_);
        ed25519PubRaw_    = std::move(other.ed25519PubRaw_);
        dilithiumPubRaw_  = std::move(other.dilithiumPubRaw_);
        x25519PrivRaw_    = std::move(other.x25519PrivRaw_);
        ed25519PrivRaw_   = std::move(other.ed25519PrivRaw_);
        dilithiumPrivRaw_ = std::move(other.dilithiumPrivRaw_);
    }
    return *this;
}

//───────────────────────────────────────────────────────────────────────────────
//  toJsonPublic(): raw → SPKI-DER → Base64 → JSON
//───────────────────────────────────────────────────────────────────────────────
nlohmann::json KeyBundle::toJsonPublic() const {
    qDebug() << "[KeyBundle::toJsonPublic] Entering. Raw public sizes:"
             << "X25519=" << x25519PubRaw_.size()
             << ", Ed25519=" << ed25519PubRaw_.size()
             << ", Dilithium=" << dilithiumPubRaw_.size();

    // 1) Wrap raw → DER (44 bytes) for X25519 and Ed25519
    std::vector<uint8_t> xDer = der::x25519(x25519PubRaw_);
    std::vector<uint8_t> eDer = der::ed25519(ed25519PubRaw_);
    qDebug().nospace()
        << "[KeyBundle::toJsonPublic] Wrapped X25519 to DER length=" << xDer.size()
        << ", Ed25519 to DER length=" << eDer.size();
    if (xDer.size() != 44 || eDer.size() != 44) {
        qWarning() << "[KeyBundle::toJsonPublic] DER wrap lengths unexpected!";
        throw std::runtime_error("KeyBundle::toJsonPublic: DER wrap error");
    }

    // 2) Base64-encode those DER blobs
    std::string kemB64 = toBase64(xDer);
    std::string edB64  = toBase64(eDer);
    qDebug().nospace()
        << "[KeyBundle::toJsonPublic] Base64 lengths: X25519=" << kemB64.size()
        << ", Ed25519=" << edB64.size();

    // 3) PQ side: raw → Base64 (no DER step)
    std::string dilB64 = toBase64(dilithiumPubRaw_);
    qDebug().nospace()
        << "[KeyBundle::toJsonPublic] Base64 length of Dilithium pub=" << dilB64.size();

    // 4) Build JSON
    nlohmann::json j;
    j["preQuantum"]["identityKemPublicKey"]     = kemB64;
    j["preQuantum"]["identitySigningPublicKey"] = edB64;
    j["postQuantum"]["identitySigningPublicKey"] = dilB64;

    qDebug() << "[KeyBundle::toJsonPublic] Returning JSON object.";
    return j;
}

//───────────────────────────────────────────────────────────────────────────────
//  fromJsonPublic(): JSON → Base64 → DER → raw
//───────────────────────────────────────────────────────────────────────────────
KeyBundle KeyBundle::fromJsonPublic(const std::string& jsonStr) {
    qDebug().nospace()
        << "[KeyBundle::fromJsonPublic] Parsing JSON (length=" << jsonStr.size() << ")";
    nlohmann::json j = nlohmann::json::parse(jsonStr);

    // Extract Base64 strings
    std::string kemB64, edB64, dilB64;
    try {
        kemB64 = j.at("preQuantum").at("identityKemPublicKey").get<std::string>();
        edB64  = j.at("preQuantum").at("identitySigningPublicKey").get<std::string>();
        dilB64 = j.at("postQuantum").at("identitySigningPublicKey").get<std::string>();
    } catch (...) {
        qWarning() << "[KeyBundle::fromJsonPublic] Missing expected JSON fields!";
        throw std::invalid_argument("KeyBundle::fromJsonPublic: missing fields");
    }
    qDebug().nospace()
        << "[KeyBundle::fromJsonPublic] Extracted Base64 lengths: X25519="
        << kemB64.size() << ", Ed25519=" << edB64.size()
        << ", Dilithium=" << dilB64.size();

    // Base64 → DER (44 bytes) → raw (32 bytes) for X25519/Ed25519
    std::vector<uint8_t> xDer  = fromBase64(kemB64, "x25519Pub");
    std::vector<uint8_t> eDer  = fromBase64(edB64,  "ed25519Pub");
    qDebug().nospace()
        << "[KeyBundle::fromJsonPublic] Decoded DER lengths: X25519="
        << xDer.size() << ", Ed25519=" << eDer.size();
    if (xDer.size() != 44 || eDer.size() != 44) {
        qWarning() << "[KeyBundle::fromJsonPublic] Unexpected DER lengths!";
        throw std::invalid_argument("KeyBundle::fromJsonPublic: DER length mismatch");
    }
    std::vector<uint8_t> xRaw = der::parseX25519Spki(xDer);
    std::vector<uint8_t> eRaw = der::parseEd25519Spki(eDer);
    qDebug().nospace()
        << "[KeyBundle::fromJsonPublic] Parsed raw lengths: X25519=" << xRaw.size()
        << ", Ed25519=" << eRaw.size();

    // Base64 → raw PQ for Dilithium-5
    std::vector<uint8_t> dilRaw = fromBase64(dilB64, "dilithiumPub");
    qDebug().nospace()
        << "[KeyBundle::fromJsonPublic] Parsed raw PQ length=" << dilRaw.size();

    qDebug() << "[KeyBundle::fromJsonPublic] Constructing public-only KeyBundle.";
    return KeyBundle(xRaw, eRaw, dilRaw);
}

//───────────────────────────────────────────────────────────────────────────────
//  toJsonPrivate(): public (DER+Base64) + private (raw+Base64)
//───────────────────────────────────────────────────────────────────────────────
nlohmann::json KeyBundle::toJsonPrivate() const {
    qDebug() << "[KeyBundle::toJsonPrivate] Entering, will include private keys too.";

    // Start from public JSON
    nlohmann::json jpub = toJsonPublic();
    qDebug() << "[KeyBundle::toJsonPrivate] Obtained public JSON portion.";

    // Copy into jpriv, then insert raw-→Base64 private keys
    nlohmann::json jpriv = jpub;
    jpriv["preQuantum"]["identityKemPrivateKey"]     = toBase64(x25519PrivRaw_);
    jpriv["preQuantum"]["identitySigningPrivateKey"] = toBase64(ed25519PrivRaw_);
    jpriv["postQuantum"]["identitySigningPrivateKey"] = toBase64(dilithiumPrivRaw_);
    qDebug().nospace()
        << "[KeyBundle::toJsonPrivate] Appended Base64-encoded private keys: "
        << "X25519Priv=" << x25519PrivRaw_.size() << " bytes raw → Base64 len="
        << toBase64(x25519PrivRaw_).size();

    return jpriv;
}

//───────────────────────────────────────────────────────────────────────────────
//  fromJsonPrivate(): parse public+private keys from JSON
//───────────────────────────────────────────────────────────────────────────────
KeyBundle KeyBundle::fromJsonPrivate(const nlohmann::json& j) {
    qDebug() << "[KeyBundle::fromJsonPrivate] Entering, JSON includes private fields.";

    // Extract Base64 strings
    std::string kemPubB64, edPubB64, kemPrivB64, edPrivB64, dilPubB64, dilPrivB64;
    try {
        auto preQ  = j.at("preQuantum");
        auto postQ = j.at("postQuantum");

        kemPubB64    = preQ.at("identityKemPublicKey").get<std::string>();
        edPubB64     = preQ.at("identitySigningPublicKey").get<std::string>();
        kemPrivB64   = preQ.at("identityKemPrivateKey").get<std::string>();
        edPrivB64    = preQ.at("identitySigningPrivateKey").get<std::string>();

        dilPubB64    = postQ.at("identitySigningPublicKey").get<std::string>();
        dilPrivB64   = postQ.at("identitySigningPrivateKey").get<std::string>();
    } catch (...) {
        qWarning() << "[KeyBundle::fromJsonPrivate] Missing expected JSON fields!";
        throw std::invalid_argument("KeyBundle::fromJsonPrivate: missing fields");
    }
    qDebug().nospace()
        << "[KeyBundle::fromJsonPrivate] Extracted Base64 for: "
        << "X25519Pub=" << kemPubB64.size()
        << ", Ed25519Pub=" << edPubB64.size()
        << ", X25519Priv=" << kemPrivB64.size()
        << ", Ed25519Priv=" << edPrivB64.size()
        << ", DilPub=" << dilPubB64.size()
        << ", DilPriv=" << dilPrivB64.size();

    // Public side: Base64 → DER (44) → raw (32)
    std::vector<uint8_t> xDerRaw  = fromBase64(kemPubB64,   "x25519Pub");
    std::vector<uint8_t> eDerRaw  = fromBase64(edPubB64,    "ed25519Pub");
    qDebug().nospace()
        << "[KeyBundle::fromJsonPrivate] Decoded DER lengths for public: "
        << "X25519=" << xDerRaw.size() << ", Ed25519=" << eDerRaw.size();
    if (xDerRaw.size() != 44 || eDerRaw.size() != 44) {
        qWarning() << "[KeyBundle::fromJsonPrivate] Unexpected DER lengths for public keys!";
        throw std::invalid_argument("KeyBundle::fromJsonPrivate: DER length mismatch");
    }
    std::vector<uint8_t> xPubRaw  = der::parseX25519Spki(xDerRaw);
    std::vector<uint8_t> ePubRaw  = der::parseEd25519Spki(eDerRaw);
    qDebug().nospace()
        << "[KeyBundle::fromJsonPrivate] Parsed raw public lengths: "
        << "X25519=" << xPubRaw.size() << ", Ed25519=" << ePubRaw.size();

    // PQ public: Base64 → raw
    std::vector<uint8_t> dPubRaw  = fromBase64(dilPubB64, "dilithiumPub");
    qDebug().nospace()
        << "[KeyBundle::fromJsonPrivate] Parsed raw Dilithium public length="
        << dPubRaw.size();

    // Private side: Base64 → raw
    std::vector<uint8_t> xPrivRaw = fromBase64(kemPrivB64, "x25519Priv");
    std::vector<uint8_t> ePrivRaw = fromBase64(edPrivB64,  "ed25519Priv");
    std::vector<uint8_t> dPrivRaw = fromBase64(dilPrivB64, "dilithiumPriv");
    qDebug().nospace()
        << "[KeyBundle::fromJsonPrivate] Parsed raw private lengths: "
        << "X25519Priv=" << xPrivRaw.size() << ", Ed25519Priv=" << ePrivRaw.size()
        << ", DilPriv=" << dPrivRaw.size();

    qDebug() << "[KeyBundle::fromJsonPrivate] Constructing full KeyBundle.";
    return KeyBundle(
        xPubRaw, ePubRaw, dPubRaw,
        xPrivRaw, ePrivRaw, dPrivRaw
        );
}

//───────────────────────────────────────────────────────────────────────────────
//  get*PrivateKeyBase64()
//───────────────────────────────────────────────────────────────────────────────
std::string KeyBundle::getX25519PrivateKeyBase64() const {
    qDebug().nospace()
        << "[KeyBundle::getX25519PrivateKeyBase64] Raw private length="
        << x25519PrivRaw_.size();
    return toBase64(x25519PrivRaw_);
}

std::string KeyBundle::getEd25519PrivateKeyBase64() const {
    qDebug().nospace()
        << "[KeyBundle::getEd25519PrivateKeyBase64] Raw private length="
        << ed25519PrivRaw_.size();
    return toBase64(ed25519PrivRaw_);
}

std::string KeyBundle::getDilithiumPrivateKeyBase64() const {
    qDebug().nospace()
        << "[KeyBundle::getDilithiumPrivateKeyBase64] Raw private length="
        << dilithiumPrivRaw_.size();
    return toBase64(dilithiumPrivRaw_);
}
