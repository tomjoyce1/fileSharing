// Set argon2 WASM path for browser usage
if (typeof window !== "undefined") {
  (window as any).ARGON2_WASM_PATH = "/argon2.wasm";
}

import React, { useState } from "react";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import sodium from "libsodium-wrappers";
import { Buffer } from "buffer";

import {
  openKeyDB,
  saveKeyToIndexedDB,
  deriveKeyFromPassword,
  getKeyFromIndexedDB,
  decryptPrivateKey,
} from "~/lib/crypto/KeyUtils";

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";

function uint8ArrayToBase64(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString("base64");
  console.log("[uint8ArrayToBase64] Input:", bytes, "Output (base64):", base64);
  return base64;
}

async function encryptPrivateKey(
  privateKey: Uint8Array,
  password: string,
): Promise<{ cipher: Uint8Array; salt: Uint8Array; iv: Uint8Array }> {
  console.log("[encryptPrivateKey] Input privateKey (Uint8Array):", privateKey);
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  console.log("[encryptPrivateKey] Generated salt (Uint8Array):", salt);
  console.log("[encryptPrivateKey] Generated iv (Uint8Array):", iv);
  const key = await deriveKeyFromPassword(password, salt);
  console.log("[encryptPrivateKey] Derived key (CryptoKey):", key);
  const cipher = new Uint8Array(
    await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      privateKey,
    ),
  );
  console.log("[encryptPrivateKey] Encrypted cipher (Uint8Array):", cipher);
  return { cipher, salt, iv };
}

// ML-DSA keygen (as in KeyHelper.ts)
async function generateMLDSAKeypair() {
  // Use 32 bytes of random for seed
  const seed = sodium.randombytes_buf(32);
  console.log("[generateMLDSAKeypair] Generated seed (Uint8Array):", seed);
  const keypair = ml_dsa87.keygen(seed);
  console.log(
    "[generateMLDSAKeypair] keypair.publicKey (Uint8Array):",
    keypair.publicKey,
  );
  console.log(
    "[generateMLDSAKeypair] keypair.secretKey (Uint8Array):",
    keypair.secretKey,
  );
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
  };
}

export default function AuthPage({
  onAuthSuccess,
}: {
  onAuthSuccess: (username: string) => void;
}) {
  const [mode, setMode] = useState<"login" | "register" | "forgot">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log(`[handleSubmit] Mode: ${mode}`);
    console.log(`[handleSubmit] Username: ${username}`);
    if (mode === "register") {
      if (username.trim() && password.trim()) {
        setError("");
        setLoading(true);
        try {
          console.log("[Register] Starting sodium");
          await sodium.ready;

          console.log("[Register] Generating keypairs...");
          const edKeypair = sodium.crypto_sign_keypair();
          console.log(
            "[Register] edKeypair.publicKey (Uint8Array):",
            edKeypair.publicKey,
          );
          console.log(
            "[Register] edKeypair.privateKey (Uint8Array):",
            edKeypair.privateKey,
          );
          const x25519Keypair = sodium.crypto_kx_keypair();
          console.log(
            "[Register] x25519Keypair.publicKey (Uint8Array):",
            x25519Keypair.publicKey,
          );
          console.log(
            "[Register] x25519Keypair.privateKey (Uint8Array):",
            x25519Keypair.privateKey,
          );
          const mldsaKeypair = await generateMLDSAKeypair();

          console.log("[Register] Encrypting private keys...");
          const edEncrypted = await encryptPrivateKey(
            edKeypair.privateKey,
            password,
          );
          console.log("[Register] edEncrypted:", edEncrypted);
          const x25519Encrypted = await encryptPrivateKey(
            x25519Keypair.privateKey,
            password,
          );
          console.log("[Register] x25519Encrypted:", x25519Encrypted);
          const mldsaEncrypted = await encryptPrivateKey(
            mldsaKeypair.privateKey,
            password,
          );
          console.log("[Register] mldsaEncrypted:", mldsaEncrypted);

          console.log("[Register] Saving encrypted keys to IndexedDB...");
          await saveKeyToIndexedDB(
            `${username}_ed25519_priv`,
            new Uint8Array([
              ...edEncrypted.salt,
              ...edEncrypted.iv,
              ...edEncrypted.cipher,
            ]),
          );
          console.log(`[Register] Saved ed25519 key for ${username}`);
          await saveKeyToIndexedDB(
            `${username}_x25519_priv`,
            new Uint8Array([
              ...x25519Encrypted.salt,
              ...x25519Encrypted.iv,
              ...x25519Encrypted.cipher,
            ]),
          );
          console.log(`[Register] Saved x25519 key for ${username}`);
          await saveKeyToIndexedDB(
            `${username}_mldsa_priv`,
            new Uint8Array([
              ...mldsaEncrypted.salt,
              ...mldsaEncrypted.iv,
              ...mldsaEncrypted.cipher,
            ]),
          );
          console.log(`[Register] Saved mldsa key for ${username}`);

          console.log("[Register] Constructing key_bundle...");
          const key_bundle = {
            preQuantum: {
              identityKemPublicKey: uint8ArrayToBase64(x25519Keypair.publicKey),
              identitySigningPublicKey: uint8ArrayToBase64(edKeypair.publicKey),
            },
            postQuantum: {
              identityKemPublicKey: uint8ArrayToBase64(x25519Keypair.publicKey), // Use x25519 as placeholder if no PQ KEM
              identitySigningPublicKey: uint8ArrayToBase64(
                mldsaKeypair.publicKey,
              ),
            },
          };
          console.log("[Register] key_bundle:", key_bundle);

          console.log("[Register] Sending registration request to server...");
          const res = await fetch("/api/keyhandler/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, key_bundle }),
          });

          console.log("[Register] Server response status:", res.status);
          if (res.ok) {
            if (keepSignedIn) {
              localStorage.setItem("drive_username", username);
              console.log(
                `[Register] Saved username to localStorage: ${username}`,
              );
            }
            setLoading(false);
            console.log("[Register] Success");
            onAuthSuccess(username);
          } else {
            const data = await res.json();
            console.error("[Register] Server error:", data);
            setError(data.message || "Registration failed");
            setLoading(false);
          }
        } catch (err: any) {
          console.error("[Register] Exception occurred:", err);
          setError("Registration error: " + err.message);
          setLoading(false);
        }
      } else {
        setError("Please enter username and password.");
      }
      return;
    }

    if (mode === "login") {
      if (username.trim() && password.trim()) {
        setError("");
        setLoading(true);
        try {
          // 1. Retrieve encrypted private keys from IndexedDB
          const edRaw = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
          const x25519Raw = await getKeyFromIndexedDB(
            `${username}_x25519_priv`,
          );
          const mldsaRaw = await getKeyFromIndexedDB(`${username}_mldsa_priv`);
          console.log("[Login] edRaw (Uint8Array):", edRaw);
          console.log("[Login] x25519Raw (Uint8Array):", x25519Raw);
          console.log("[Login] mldsaRaw (Uint8Array):", mldsaRaw);
          if (!edRaw || !x25519Raw || !mldsaRaw) {
            setError("No keys found for this user. Please register first.");
            setLoading(false);
            return;
          }
          // 2. Extract salt, iv, cipher for each
          const edSalt = edRaw.slice(0, 16);
          const edIv = edRaw.slice(16, 28);
          const edCipher = edRaw.slice(28);
          const x25519Salt = x25519Raw.slice(0, 16);
          const x25519Iv = x25519Raw.slice(16, 28);
          const x25519Cipher = x25519Raw.slice(28);
          const mldsaSalt = mldsaRaw.slice(0, 16);
          const mldsaIv = mldsaRaw.slice(16, 28);
          const mldsaCipher = mldsaRaw.slice(28);
          console.log(
            "[Login] edSalt:",
            edSalt,
            "edIv:",
            edIv,
            "edCipher:",
            edCipher,
          );
          console.log(
            "[Login] x25519Salt:",
            x25519Salt,
            "x25519Iv:",
            x25519Iv,
            "x25519Cipher:",
            x25519Cipher,
          );
          console.log(
            "[Login] mldsaSalt:",
            mldsaSalt,
            "mldsaIv:",
            mldsaIv,
            "mldsaCipher:",
            mldsaCipher,
          );
          // 3. Decrypt with password
          await decryptPrivateKey(edCipher, password, edSalt, edIv);
          console.log("[Login] Decrypted ed25519 private key successfully");
          await decryptPrivateKey(x25519Cipher, password, x25519Salt, x25519Iv);
          console.log("[Login] Decrypted x25519 private key successfully");
          await decryptPrivateKey(mldsaCipher, password, mldsaSalt, mldsaIv);
          console.log("[Login] Decrypted mldsa private key successfully");
          // If decryption succeeds, login is successful
          if (keepSignedIn) {
            localStorage.setItem("drive_username", username);
            console.log(`[Login] Saved username to localStorage: ${username}`);
          }
          setLoading(false);
          onAuthSuccess(username);
        } catch (err: any) {
          console.error("[Login] Exception occurred:", err);
          setError("Login failed: Incorrect password or corrupted keys.");
          setLoading(false);
        }
      } else {
        setError("Please enter username and password.");
      }
    } else if (mode === "forgot") {
      if (email.trim()) {
        setError("");
        alert("Password reset link sent to " + email);
        setMode("login");
      } else {
        setError("Please enter your email.");
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-900">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-lg bg-gray-800 p-8 shadow-lg"
      >
        <h2 className="mb-6 text-center text-2xl font-bold text-white">
          {mode === "login"
            ? "Login"
            : mode === "register"
              ? "Register"
              : "Forgot Password"}
        </h2>
        {mode !== "forgot" && (
          <div className="mb-4">
            <label className="mb-2 block text-gray-300">Username</label>
            <Input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded bg-gray-700 px-3 py-2 text-white focus:outline-none"
              autoFocus
            />
          </div>
        )}
        {mode !== "forgot" && (
          <div className="mb-4">
            <label className="mb-2 block text-gray-300">Password</label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded bg-gray-700 px-3 py-2 text-white focus:outline-none"
            />
          </div>
        )}
        {mode === "forgot" && (
          <div className="mb-4">
            <label className="mb-2 block text-gray-300">Email</label>
            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded bg-gray-700 px-3 py-2 text-white focus:outline-none"
              autoFocus
            />
          </div>
        )}
        {mode === "login" && (
          <div className="mb-4 flex items-center">
            <input
              type="checkbox"
              id="keepSignedIn"
              checked={keepSignedIn}
              onChange={() => setKeepSignedIn((v) => !v)}
              className="mr-2"
            />
            <label htmlFor="keepSignedIn" className="text-sm text-gray-300">
              Keep me signed in
            </label>
          </div>
        )}
        {error && <div className="mb-4 text-sm text-red-400">{error}</div>}
        <Button
          type="submit"
          className="mb-2 w-full bg-blue-600 hover:bg-blue-700"
          disabled={loading}
        >
          {loading
            ? mode === "register"
              ? "Registering..."
              : "Loading..."
            : mode === "login"
              ? "Login"
              : mode === "register"
                ? "Register"
                : "Send Reset Link"}
        </Button>
        <div className="mt-2 flex justify-between text-sm">
          {mode !== "login" && (
            <button
              type="button"
              className="text-blue-400 hover:underline"
              onClick={() => setMode("login")}
            >
              Back to Login
            </button>
          )}
          {mode === "login" && (
            <>
              <button
                type="button"
                className="text-blue-400 hover:underline"
                onClick={() => setMode("register")}
              >
                Register
              </button>
              <button
                type="button"
                className="ml-4 text-blue-400 hover:underline"
                onClick={() => setMode("forgot")}
              >
                Forgot Password?
              </button>
            </>
          )}
        </div>
      </form>
    </div>
  );
}
