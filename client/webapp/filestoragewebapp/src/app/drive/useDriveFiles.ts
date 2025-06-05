import { useState, useEffect } from "react";
import type { FileMetadataListItem } from "@/lib/types";
import { createAuthenticatedRequest } from "./utils/encryption";
import { getDecryptedPrivateKey } from '@/components/AuthPage';

export function useDriveFiles(
  page: number, 
  setError: (msg: string | null) => void, 
  setIsLoading: (b: boolean) => void,
  refreshTrigger: number = 0
) {
  const [files, setFiles] = useState<FileMetadataListItem[]>([]);
  const [hasNextPage, setHasNextPage] = useState(false);

  useEffect(() => {
    const fetchFiles = async () => {
      const username = localStorage.getItem("drive_username");
      let password = (window as any).inMemoryPassword;
      if (!username) {
        setError("Not logged in. Please log in first.");
        setFiles([]);
        setHasNextPage(false);
        return;
      } else {
        setError(null);
      }
      if (!password) {
        setError('Please log in again to view your files.');
        setFiles([]);
        setHasNextPage(false);
        return;
      }
      setIsLoading(true);
      try {
        const ed25519Priv = await getDecryptedPrivateKey(username, 'ed25519', password);
        const mldsaPriv = await getDecryptedPrivateKey(username, 'mldsa', password);

        if (!ed25519Priv || !mldsaPriv) {
          setError("Could not load your private keys. Please log in again.");
          setFiles([]);
          setHasNextPage(false);
          return;
        }

        const privateKeyBundle = {
          preQuantum: {
            identitySigning: { privateKey: ed25519Priv },
          },
          postQuantum: {
            identitySigning: { privateKey: mldsaPriv },
          },
        };
        const body = { page };
        const { headers, body: bodyString } = createAuthenticatedRequest(
          "POST",
          "/api/fs/list",
          body,
          username,
          privateKeyBundle
        );

        const response = await fetch("/api/fs/list", {
          method: "POST",
          headers,
          body: bodyString,
        });

        if (response.status === 401) {
          const errorText = await response.text();
          setError("Authentication failed. Please try clicking Retry. If that doesn't work, you may need to log in again.");
          setFiles([]);
          setHasNextPage(false);
          return;
        }
        if (!response.ok) throw new Error("Failed to fetch files");
        const { fileData, hasNextPage } = await response.json();
        setFiles(fileData);
        setHasNextPage(hasNextPage);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch files");
        setFiles([]);
        setHasNextPage(false);
      } finally {
        setIsLoading(false);
      }
    };
    void fetchFiles();
  }, [page, refreshTrigger]);

  return { files, hasNextPage };
}
