import { useState, useEffect } from "react";
import sodium from "libsodium-wrappers";
import type { FileMetadataListItem } from "@/lib/types";
import { getPrivateKeyFromIndexedDB } from "@/lib/crypto/KeyUtils";

export function useDriveFiles(page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const [files, setFiles] = useState<FileMetadataListItem[]>([]);
  const [hasNextPage, setHasNextPage] = useState(false);

  const fetchFiles = async (pageNumber: number) => {
    const username = localStorage.getItem("drive_username");
    if (!username) {
      setError("Not logged in. Please log in first.");
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      const message = JSON.stringify({ page: pageNumber });
      await sodium.ready;
      const edPrivateKey = await getPrivateKeyFromIndexedDB(`${username}_ed25519_priv`);
      if (!edPrivateKey) {
        setError("Your login keys are not available yet. Please wait a moment and click Retry.");
        return;
      }
      const dataToSign = new TextEncoder().encode(message);
      const signature = Buffer.from(
        sodium.crypto_sign_detached(dataToSign, edPrivateKey)
      ).toString('base64');
      const headers = {
        'Content-Type': 'application/json',
        'X-Username': username,
        'X-Signature': signature,
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
  };

  // Retry logic
  const retryFetchFiles = async (pageNumber: number, maxRetries = 3) => {
    let lastError = null;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        await fetchFiles(pageNumber);
        return;
      } catch (err) {
        lastError = err;
        if (attempt < maxRetries) {
          await new Promise(res => setTimeout(res, 1000 * attempt));
          continue;
        }
      }
    }
    if (lastError) {
      setError("Failed to load files after multiple attempts. You may need to log in again.");
    }
  };

  useEffect(() => {
    void retryFetchFiles(page);
    // eslint-disable-next-line
  }, [page]);

  return { files, hasNextPage, fetchFiles };
}
