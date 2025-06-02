import sodium from "libsodium-wrappers";
import { getKeyFromIndexedDB } from "@/lib/crypto/KeyUtils";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";

export async function fetchFiles(
  pageNumber: number,
  username: string,
  password: string,
  setError: (msg: string | null) => void,
  setIsLoading: (b: boolean) => void,
  setFiles: (files: any[]) => void,
  setHasNextPage: (hasNext: boolean) => void
): Promise<void> {
  try {
    setIsLoading(true);
    setError(null);
    const body = { page: pageNumber };
    const bodyString = JSON.stringify(body);
    await sodium.ready;
    const edPrivateKey = await getKeyFromIndexedDB(`${username}_ed25519_priv`, password);
    const mldsaPrivateKey = await getKeyFromIndexedDB(`${username}_mldsa_priv`, password);
    if (!edPrivateKey || !mldsaPrivateKey) {
      setError("Your login keys are not available yet. Please wait a moment and click Retry.");
      return;
    }
    const timestamp = new Date().toISOString(); // Generate timestamp
    const canonicalString = `${username}|${timestamp}|POST|/api/fs/list|${bodyString}`;
    const canonicalBytes = new TextEncoder().encode(canonicalString);
    // Ed25519 signature
    const preQuantumSig = Buffer.from(
      sodium.crypto_sign_detached(canonicalBytes, edPrivateKey)
    ).toString("base64");
    // ML-DSA-87 signature
    const postQuantumSig = Buffer.from(
      ml_dsa87.sign(mldsaPrivateKey, canonicalBytes)
    ).toString("base64");
    // Include timestamp in headers
    const headers = {
      "Content-Type": "application/json",
      "X-Username": username,
      "X-Timestamp": timestamp,
      "X-Signature-PreQuantum": preQuantumSig,
      "X-Signature-PostQuantum": postQuantumSig,
    };
    // Log canonical string and file content for debugging
    console.log("[Debug] Frontend Canonical String:", canonicalString.substring(0, 200));
    console.log("[Debug] Frontend Request Body:", bodyString.substring(0, 200));
    const response = await fetch("/api/fs/list", {
      method: "POST",
      headers,
      body: bodyString,
    });
    if (response.status === 401) {
      const errorText = await response.text();
      setError("Authentication failed. Please try clicking Retry. If that doesn't work, you may need to log in again.");
      return;
    }
    if (!response.ok) {
      throw new Error("Failed to fetch files");
    }
    const { fileData, hasNextPage } = await response.json();
    setFiles(fileData);
    setHasNextPage(hasNextPage);
    setError(null);

    console.log("[Debug]frontend final big one Canonical String:", canonicalString);

  } catch (err) {
    setError(err instanceof Error ? err.message : "Failed to fetch files");
    setFiles([]);
  } finally {
    setIsLoading(false);
  }
}
