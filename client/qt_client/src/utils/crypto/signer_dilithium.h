#pragma once
#include "Signer.h"
#include <oqs/oqs.h>
#include <vector>
#include <cstdint>

/**
 * Signer_Dilithium → actually ML-DSA-87 (Dilithium-5 parameter set)
 *
 * Uses liboqs via OQS_SIG_alg_ml_dsa_87 so that key sizes match “ml_dsa87”
 * in @noble/post-quantum.
 *
 * Chris C++ Requirements:
 * - Constructors and Destructors
 */
class Signer_Dilithium : public Signer {
public:
    Signer_Dilithium();                       /* creates ML-DSA-87 context   */
    ~Signer_Dilithium() override;

    // forbid copy, allow move
    Signer_Dilithium(const Signer_Dilithium&)            = delete;
    Signer_Dilithium& operator=(const Signer_Dilithium&) = delete;
    Signer_Dilithium(Signer_Dilithium&&)  noexcept       = default;
    Signer_Dilithium& operator=(Signer_Dilithium&&) noexcept = default;

    // Signer interface --------------------------------------------------------
    void                keygen() override;
    std::vector<uint8_t> pub()  const override;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const override;
    bool verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& sig) const override;

    // helpers -----------------------------------------------------------------
    void   loadPrivateKey(const uint8_t* sk, size_t len);  // import existing sk
    void loadPublicKey (const uint8_t* rawPk, size_t len);

    size_t skLength()      const { return _oqs->length_secret_key; }
    const uint8_t* getSecretKeyBuffer() const { return _sk.data(); }

private:
    OQS_SIG*             _oqs;   /* liboqs context for ML-DSA-87            */
    std::vector<uint8_t> _pk;    /* public key  (2 592 bytes)               */
    std::vector<uint8_t> _sk;    /* secret key (4 896 bytes)                */
};
