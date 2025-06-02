#pragma once
#include "Signer.h"
#include <oqs/oqs.h>
#include <vector>
#include <cstdint>

/**
 * Signer_Dilithium
 *
 * Post-quantum digital signature using CRYSTALS-Dilithium (via liboqs).
 */
class Signer_Dilithium : public Signer {
public:
    Signer_Dilithium();
    ~Signer_Dilithium() override;

    // forbid copy, allow move
    Signer_Dilithium(const Signer_Dilithium&);
    Signer_Dilithium& operator=(const Signer_Dilithium&);
    Signer_Dilithium(Signer_Dilithium&&) noexcept = default;
    Signer_Dilithium& operator=(Signer_Dilithium&&) noexcept = default;

    // Inherited Signer interface
    void keygen() override;
    std::vector<uint8_t> pub() const override;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const override;
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& signature) const override;

    // ← NEW: load an existing Dilithium secret key (exact length = _oqs->length_secret_key)
    void loadPrivateKey(const uint8_t* rawSk, size_t len);

    // ← NEW: return the secret‐key length (so caller knows how big to supply)
    size_t skLength() const { return static_cast<size_t>(_oqs->length_secret_key); }

    // ← NEW: get a pointer to the raw secret‐key buffer
    const uint8_t* getSecretKeyBuffer() const { return _sk.data(); }

private:
    OQS_SIG*             _oqs;  // the OQS signature context (Dilithium5)
    std::vector<uint8_t> _pk;   // public key (length = _oqs->length_public_key)
    std::vector<uint8_t> _sk;   // secret key (length = _oqs->length_secret_key)
};
