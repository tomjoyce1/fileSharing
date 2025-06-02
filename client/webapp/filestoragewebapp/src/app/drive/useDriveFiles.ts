import { useState, useEffect } from "react";
import type { FileMetadataListItem } from "@/lib/types";
import { fetchFiles } from "./useFetchFiles";
import { retryFetchFiles } from "./useRetryFetch";

export function useDriveFiles(page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const [files, setFiles] = useState<FileMetadataListItem[]>([]);
  const [hasNextPage, setHasNextPage] = useState(false);

  useEffect(() => {
    const username = localStorage.getItem("drive_username");
    const password = localStorage.getItem("drive_password");
    if (!username || !password) {
      setError("Not logged in. Please log in first.");
      return;
    }

    const fetchFilesWrapper = async (pageNumber: number) => {
      await fetchFiles(
        pageNumber,
        username,
        password,
        setError,
        setIsLoading,
        setFiles,
        setHasNextPage
      );
    };

    void retryFetchFiles(page, fetchFilesWrapper, setError);
    // eslint-disable-next-line
  }, [page]);

  return { files, hasNextPage };
}
