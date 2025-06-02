import { useEffect } from "react";
import { validateUserKeys } from "@/lib/crypto/KeyUtils";

export function useKeyValidation(page: number, setError: (msg: string|null) => void, retryFetchFiles: (page: number) => void) {
  useEffect(() => {
    const validateKeys = async () => {
      const username = localStorage.getItem("drive_username");
      if (!username) {
        setError("Not logged in. Please log in first.");
        return;
      }
      try {
        const keysValid = await validateUserKeys(username);
        if (!keysValid) {
          setError("Your login keys appear to be invalid. Please try clicking Retry, or log in again if the problem persists.");
          return;
        }
        void retryFetchFiles(page);
      } catch (err) {
        setError("Failed to validate login keys. Please try clicking Retry.");
      }
    };
    void validateKeys();
    // eslint-disable-next-line
  }, []);
}
