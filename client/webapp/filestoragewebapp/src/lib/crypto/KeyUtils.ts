// ~/lib/crypto/keyUtils.ts

import sodium from "libsodium-wrappers";

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
    request.onerror = () => reject(request.error);
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
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readonly");
    const req = tx.objectStore("keys").get(keyName);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(new Error(String(req.error)));
  });
}

export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  if (typeof window === "undefined") {
    throw new Error("deriveKeyFromPassword must only be called client-side");
  }
  await sodium.ready;
  // Dynamically import argon2-browser only on client
  const argon2 = (await import("argon2-browser")).default;
  // Argon2id parameters
  // Convert salt Uint8Array to base64 string for argon2-browser
  const saltBase64 = btoa(String.fromCharCode(...salt));
  const argon2Params = {
    pass: password,
    salt: saltBase64,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: 3, // iterations
    mem: 64 * 1024, // 64 MB
    parallelism: 1,
    raw: true,
  };
  const argon2Result = await argon2.hash(argon2Params);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    argon2Result.hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  return keyMaterial;
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
