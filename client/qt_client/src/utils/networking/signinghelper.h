#pragma once

#include <string>

class SigningHelper {
public:
    /**
     * Returns the current UTC timestamp as an ISO8601 string,
     * e.g. "2025-06-01T12:34:56Z".
     */
    static std::string currentTimestamp();

    /**
     * Creates a “hybrid” signature by concatenating an Ed25519 signature
     * and a Dilithium2 signature (both assumed Base64‐encoded), separated by "||".
     *
     * @param username      The username string
     * @param timestamp     The timestamp string
     * @param method        The HTTP method (e.g. "POST")
     * @param path          The request path (e.g. "/login")
     * @param body          The request body (JSON‐encoded)
     * @param ed25519Sk     Base64‐encoded Ed25519 secret key
     * @param dilithiumSk   Base64‐encoded Dilithium2 secret key
     * @return              A single string: Base64(Ed25519(sig)) + "||" + Base64(Dilithium2(sig))
     */
    static std::string createHybridSignature(
        const std::string& username,
        const std::string& timestamp,
        const std::string& method,
        const std::string& path,
        const std::string& body,
        const std::string& ed25519Sk,
        const std::string& dilithiumSk
        );
};
