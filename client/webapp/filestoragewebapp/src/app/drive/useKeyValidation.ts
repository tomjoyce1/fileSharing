import { useEffect } from "react";

export function useKeyValidation(page: number, setError: (msg: string|null) => void, retryFetchFiles: (page: number) => void) {
  useEffect(() => {
    const validateKeys = async () => {
      const username = localStorage.getItem("drive_username");
      if (!username) {
        setError("Not logged in. Please log in first.");
        return;
      }
      try {
        // Directly retry fetching files without key validation
        void retryFetchFiles(page);
      } catch (err) {
        setError("Failed to validate login keys. Please try clicking Retry.");
      }
    };

    void validateKeys();
  }, [page, retryFetchFiles, setError]);
}
