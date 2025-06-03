import { gcm } from '@noble/ciphers/aes';
import { getKeyFromIndexedDB } from '@/lib/crypto/KeyUtils';
import type { FileItem } from "./driveTypes";

// Placeholder types for missing definitions
type DriveItem = { id: string; type: string };
type FileMetadataListItem = { id: string; metadata: string };
type FileMetadata = { id: string; decryptedMetadata: string };

export function useFileActions(fetchFiles: (page: number) => Promise<void>, page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const ensureFileItem = (item: any): FileItem => {
    // Use all required fields for FileItem
    return {
      id: item.id,
      name: item.name || "Unknown",
      type: "file",
      fileType: item.fileType || "document",
      size: item.size || "-",
      modified: item.modified || "-",
      url: item.url || '',
      encrypted: item.encrypted || false,
    };
  };

  const handleDelete = (item: any) => {
    const fileItem = ensureFileItem(item);
    void (async () => {
      try {
        const response = await fetch(`/api/fs/delete/${fileItem.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        if (!response.ok) throw new Error('Failed to delete file');
        void fetchFiles(page);
      } catch (err) {
        setError('Failed to delete file');
      }
    })();
  };

  const handleRename = (item: any): FileItem => {
    const fileItem = ensureFileItem(item);
    const newName = prompt("Enter new name", fileItem.name);
    if (!newName || newName === fileItem.name) return fileItem;
    void (async () => {
      try {
        const response = await fetch(`/api/fs/rename/${fileItem.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ newName })
        });
        if (!response.ok) throw new Error('Failed to rename file');
        void fetchFiles(page);
      } catch (err) {
        setError('Failed to rename file');
      }
    })();
    return { ...fileItem, name: newName };
  };

  // --- New: Decrypt metadata ---
  const decryptMetadata = async (file: any) => {
    // Try to get client_data from localStorage (should be stored after upload)
    const clientDataStr = localStorage.getItem(`client_data_${file.file_id}`);
    if (!clientDataStr) throw new Error('Missing decryption keys for this file.');
    const clientData = JSON.parse(clientDataStr);
    // Prompt for password if needed
    const username = localStorage.getItem('drive_username') || '';
    let password = localStorage.getItem('drive_password') || '';
    if (!password) {
      password = window.prompt('Enter your password to unlock your keys:') || '';
      if (!password) throw new Error('Password required to unlock keys');
    }
    // Load MEK from clientData
    const mek = new Uint8Array(clientData.mek);
    const metadataNonce = new Uint8Array(clientData.metadataNonce);
    // Decrypt metadata
    const encryptedMetadata = typeof file.metadata === 'string' ? Uint8Array.from(atob(file.metadata), c => c.charCodeAt(0)) : file.metadata;
    const decrypted = gcm(mek, metadataNonce).decrypt(encryptedMetadata);
    return JSON.parse(new TextDecoder().decode(decrypted));
  };

  // --- New: Handle file open (download and decrypt) ---
  const handleFileOpen = async (file: any) => {
    try {
      // Try to get client_data from localStorage
      const clientDataStr = localStorage.getItem(`client_data_${file.file_id}`);
      if (!clientDataStr) throw new Error('Missing decryption keys for this file.');
      const clientData = JSON.parse(clientDataStr);
      // Prompt for password if needed
      const username = localStorage.getItem('drive_username') || '';
      let password = localStorage.getItem('drive_password') || '';
      if (!password) {
        password = window.prompt('Enter your password to unlock your keys:') || '';
        if (!password) throw new Error('Password required to unlock keys');
      }
      // Load FEK and fileNonce from clientData
      const fek = new Uint8Array(clientData.fek);
      const fileNonce = new Uint8Array(clientData.fileNonce);
      // Download encrypted file content
      const res = await fetch(`/api/fs/download`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Username': username },
        body: JSON.stringify({ file_id: file.file_id })
      });
      if (!res.ok) throw new Error('Failed to download file');
      const data = await res.json();
      const encryptedContent = Uint8Array.from(atob(data.file_content), c => c.charCodeAt(0));
      // Decrypt file content
      const decrypted = gcm(fek, fileNonce).decrypt(encryptedContent);
      // Download as file
      const blob = new Blob([decrypted]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name || 'downloaded_file';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return { handleDelete, handleRename, ensureFileItem, decryptMetadata, handleFileOpen };
}

// Placeholder for any remaining valid imports

// Placeholder for valid logic related to file actions
export async function fetchFileMetadata(fileId: string) {
  console.log(`[useFileActions] Fetching metadata for fileId=${fileId}`);
  // Add valid logic here if needed
}
