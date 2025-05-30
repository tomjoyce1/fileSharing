import argon2 from "argon2-browser";

export async function openKeyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("DriveKeysDB", 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("keys")) {
        db.createObjectStore("keys");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error(String(request.error)));
  });
}

export async function saveKeyToIndexedDB(keyName: string, keyData: Uint8Array) {
  const db = await openKeyDB();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").put(keyData, keyName);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error(String(tx.error)));
  });
}

export async function getKeyFromIndexedDB(
  keyName: string,
): Promise<Uint8Array | null> {
  const db = await openKeyDB();
  return new Promise<Uint8Array | null>((resolve, reject) => {
    const tx = db.transaction("keys", "readonly");
    const req = tx.objectStore("keys").get(keyName);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(new Error(String(req.error)));
  });
}

// ---- insert deriveKeyFromPassword ----

export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  // Defensive: ensure salt is Uint8Array and not base64 or string
  if (!(salt instanceof Uint8Array)) {
    throw new Error("Salt must be a Uint8Array, got: " + typeof salt);
  }
  // Defensive: check for accidental string salt
  if (typeof salt === "string") {
    throw new Error("Salt must not be a string");
  }
  // Defensive: check for accidental base64 salt
  if (Array.isArray(salt)) {
    throw new Error("Salt must not be an array");
  }
  // Defensive: check for accidental Buffer (Node.js)
  if (typeof Buffer !== "undefined" && salt instanceof Buffer) {
    throw new Error("Salt must not be a Buffer");
  }
  // Defensive: check for accidental object with atob method (browser base64)
  if (
    salt &&
    typeof salt === "object" &&
    typeof (salt as any).atob === "function"
  ) {
    throw new Error("Salt must not be a base64 object");
  }
  // Defensive: check for accidental stringified array
  if (
    typeof salt === "object" &&
    salt !== null &&
    salt.constructor === Object
  ) {
    throw new Error("Salt must not be a plain object");
  }
  // Log salt bytes for debugging
  console.log("[deriveKeyFromPassword] password:", password);
  console.log(
    "[deriveKeyFromPassword] salt (Uint8Array):",
    salt,
    "length:",
    salt.length,
    "bytes:",
    Array.from(salt),
  );
  // Derive a 256-bit (32-byte) key using Argon2id
  const hashResult = await argon2.hash({
    pass: password,
    salt,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32, // 32 bytes = 256 bits for AES-256
    time: 3, // Number of iterations (customize as needed)
    mem: 65536, // Memory in KB (customize as needed, e.g., 64MB)
    parallelism: 1,
    raw: true, // Get raw Uint8Array output
  });
  console.log("[deriveKeyFromPassword] argon2.hash result:", hashResult);
  // Import the derived key into WebCrypto as an AES-GCM CryptoKey
  const key = await crypto.subtle.importKey(
    "raw",
    hashResult.hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  console.log("[deriveKeyFromPassword] WebCrypto key:", key);
  return key;
}

export async function decryptPrivateKey(
  cipher: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveKeyFromPassword(password, salt);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher),
  );
  return plain;
}

// Helper: Convert Uint8Array to base64 string
export function uint8ArrayToBase64(arr: Uint8Array): string {
  return Buffer.from(arr).toString("base64");
}
