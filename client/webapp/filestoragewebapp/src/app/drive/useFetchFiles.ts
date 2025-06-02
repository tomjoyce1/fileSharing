import sodium from "libsodium-wrappers";
import { getKeyFromIndexedDB } from "@/lib/crypto/KeyUtils";

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
    const message = JSON.stringify({ page: pageNumber });
    await sodium.ready;
    const edPrivateKey = await getKeyFromIndexedDB(`${username}_ed25519_priv`, password);
    if (!edPrivateKey) {
      setError("Your login keys are not available yet. Please wait a moment and click Retry.");
      return;
    }
    const dataToSign = new TextEncoder().encode(message);
    const signature = Buffer.from(
      sodium.crypto_sign_detached(dataToSign, edPrivateKey)
    ).toString("base64");
    const headers = {
      "Content-Type": "application/json",
      "X-Username": username,
      "X-Signature": signature,
    };
    const response = await fetch("/api/fs/list", {
      method: "POST",
      headers,
      body: message,
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
  } catch (err) {
    setError(err instanceof Error ? err.message : "Failed to fetch files");
    setFiles([]);
  } finally {
    setIsLoading(false);
  }
}
