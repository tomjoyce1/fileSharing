import { deriveFEK, deriveMEK, decryptFileBuffer, decryptMetadataWithMEK } from "@/lib/crypto/encryptor";
import { getEncryptionKeys } from "@/lib/crypto/KeyUtils";
import type { FileItem, DriveItem, FileMetadataListItem, FileMetadata } from "../driveTypes";

export function useFileActions(fetchFiles: (page: number) => Promise<void>, page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const ensureFileItem = (item: DriveItem): FileItem => {
    if (item.type !== "file") throw new Error("Expected file item");
    return item;
  };

  const handleDelete = (item: DriveItem) => {
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

  const handleRename = (item: DriveItem): FileItem => {
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

  const handleFileOpen = async (file: FileItem) => {
    if (!file.encrypted || !file.url) {
      window.open(file.url, "_blank");
      return;
    }
    const response = await fetch(file.url);
    const encryptedArrayBuffer = await response.arrayBuffer();
    const s_pre = new Uint8Array(
      JSON.parse(localStorage.getItem(`fek_${file.id}_s_pre`) ?? "[]") as number[]
    );
    const s_post = new Uint8Array(
      JSON.parse(localStorage.getItem(`fek_${file.id}_s_post`) ?? "[]") as number[]
    );
    const nonce = new Uint8Array(
      JSON.parse(localStorage.getItem(`fek_${file.id}_nonce`) ?? "[]") as number[]
    );
    const fek = await deriveFEK(s_pre, s_post);
    const decryptedBuffer = await decryptFileBuffer(fek, new Uint8Array(encryptedArrayBuffer), nonce);
    const blob = new Blob([decryptedBuffer]);
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  };

  const decryptMetadata = async (file: FileMetadataListItem): Promise<FileMetadata> => {
    try {
      const keys = await getEncryptionKeys(file.id);
      if (!keys) throw new Error('Missing encryption keys');
      const s_pre = new Uint8Array(keys.s_pre);
      const s_post = new Uint8Array(keys.s_post);
      const fek = await deriveFEK(s_pre, s_post);
      const mek = await deriveMEK(fek);
      const metadataNonce = new Uint8Array(keys.metadata_nonce);
      let encryptedMetadata: Uint8Array;
      if (typeof file.metadata === 'string') {
        encryptedMetadata = Uint8Array.from(atob(file.metadata), c => c.charCodeAt(0));
      } else {
        encryptedMetadata = file.metadata as Uint8Array;
      }
      const clientData = await decryptMetadataWithMEK(mek, encryptedMetadata, metadataNonce);
      return {
        original_filename: clientData.filename || 'Unknown File',
        file_size_bytes: clientData.size || 0,
        file_type: clientData.type || 'application/octet-stream'
      };
    } catch (err) {
      return {
        original_filename: 'Unknown File',
        file_size_bytes: 0,
        file_type: 'application/octet-stream'
      };
    }
  };

  return { handleDelete, handleRename, handleFileOpen, decryptMetadata, ensureFileItem };
}
