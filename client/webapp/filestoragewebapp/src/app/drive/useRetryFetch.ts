export async function retryFetchFiles(
  pageNumber: number,
  fetchFiles: (pageNumber: number) => Promise<void>,
  setError: (msg: string | null) => void,
  maxRetries = 3
): Promise<void> {
  let lastError = null;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await fetchFiles(pageNumber);
      return;
    } catch (err) {
      lastError = err;
      if (attempt < maxRetries) {
        await new Promise((res) => setTimeout(res, 1000 * attempt));
        continue;
      }
    }
  }
  if (lastError) {
    setError("Failed to load files after multiple attempts. You may need to log in again.");
  }
}
