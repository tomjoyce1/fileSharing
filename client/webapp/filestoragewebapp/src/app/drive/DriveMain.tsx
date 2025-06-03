import React, { useState, useRef } from "react";
import DriveList from "@/components/DriveList";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useDriveFiles } from "./useDriveFiles";
import { useFileActions } from "./useFileActions";
import { useKeyValidation } from "./useKeyValidation";
import type { FileItem, DriveItem } from "./driveTypes";
import { uploadFile } from "./utils/encryption";
import { getKeyFromIndexedDB, saveKeyToIndexedDB, getObjectFromIndexedDB, saveObjectToIndexedDB } from "@/lib/crypto/KeyUtils";
import { ctr } from '@noble/ciphers/aes';

export default function DriveMain() {
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const { files, hasNextPage } = useDriveFiles(page, setError, setIsLoading);

  // Dont use dummy async function for fetchFiles in useFileActions and useKeyValidation
  const dummyAsync = async (_page: number) => {};
  const { handleDelete, handleRename, handleFileOpen, decryptMetadata, ensureFileItem } = useFileActions(dummyAsync, page, setError, setIsLoading);
  useKeyValidation(page, setError, dummyAsync);

  // Processed files for display
  const [processedFiles, setProcessedFiles] = useState<FileItem[]>([]);
  React.useEffect(() => {
    const processFiles = async () => {
      if (!files || files.length === 0) {
        setProcessedFiles([]);
        return;
      }
      const processed = await Promise.all(
        files.map(async (file) => {
          try {
            // Try IndexedDB first
            let clientData = null;
            try {
              clientData = await getObjectFromIndexedDB(file.file_id.toString());
              console.log(`[DriveMain][List] getObjectFromIndexedDB(${file.file_id}):`, clientData);
            } catch (e) {
              console.warn(`[DriveMain][List] Error reading from IndexedDB for file_id=${file.file_id}:`, e);
            }
            // Fallback to localStorage for backward compatibility
            if (!clientData) {
              const clientDataStr = localStorage.getItem(`client_data_${file.file_id}`);
              if (clientDataStr) {
                clientData = JSON.parse(clientDataStr);
                console.log(`[DriveMain][List] Fallback to localStorage for file_id=${file.file_id}:`, clientData);
              }
            }
            if (!clientData) throw new Error('Missing decryption keys for this file.');
            const mek = new Uint8Array(clientData.mek);
            const metadataNonce = new Uint8Array(clientData.metadataNonce || clientData.metadata_nonce);


            // loggin
            console.log("MEK length:", mek.length, "Expected 32");
            console.log("metadataNonce length:", metadataNonce.length, "Expected 16");
            console.log("MEK:", mek);
            console.log("metadataNonce:", metadataNonce);
            

            const encryptedMetadata = typeof file.metadata === 'string'
              ? Uint8Array.from(atob(file.metadata), c => c.charCodeAt(0))
              : file.metadata;

            const metadataCipher = ctr(mek, metadataNonce);
            const decryptedMetadataBytes = metadataCipher.decrypt(encryptedMetadata);
            const metadataString = new TextDecoder().decode(decryptedMetadataBytes);
            const metadata = JSON.parse(metadataString);

            console.log(`[DriveMain][List] Decrypted metadata for file_id=${file.file_id}:`, metadata);
            let fileType: FileItem["fileType"] = 'document';
            if (metadata.file_type?.startsWith('image')) fileType = 'image';
            else if (metadata.file_type?.startsWith('audio')) fileType = 'audio';
            else if (metadata.file_type?.startsWith('video')) fileType = 'video';
            else if (metadata.file_type === 'application/pdf') fileType = 'pdf';
            return {
              id: file.file_id?.toString() ?? '',
              name: metadata.original_filename,
              type: 'file' as const,
              fileType,
              size: metadata.file_size_bytes ? `${(metadata.file_size_bytes / (1024 * 1024)).toFixed(1)} MB` : '-',
              modified: file.upload_timestamp
                ? new Date(file.upload_timestamp * 1000).toLocaleDateString()
                : '-',
              url: `/api/fs/download/${file.file_id}`,
              encrypted: true
            };
          } catch (e) {
            // If decryption fails, skip file
            console.warn(`[DriveMain][List] Failed to decrypt metadata for file_id=${file.file_id}:`, file, e);
            return null;
          }
        })
      );
      setProcessedFiles(processed.filter(Boolean) as FileItem[]);
    };
    void processFiles();
  }, [files]);

  React.useEffect(() => {
    if (error && error.includes('Not logged in')) {
      alert(error);
    }
  }, [error]);

  const filteredItems = processedFiles.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleUpload = () => {
    if (fileInputRef.current) fileInputRef.current.click();
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    try {
      // Read file as ArrayBuffer
      const arrayBuffer = await file.arrayBuffer();
      const fileContent = new Uint8Array(arrayBuffer);
      // Prepare metadata
      const metadata = {
        original_filename: file.name,
        file_size_bytes: file.size,
        file_type: file.type || "application/octet-stream",
      };
      // Get user info
      const username = localStorage.getItem("drive_username") || "";
      if (!username) throw new Error("Not logged in");
      // Prompt for password if not in memory
      let password = localStorage.getItem("drive_password") || "";
      if (!password) {
        password = window.prompt("Enter your password to unlock your keys:") || "";
        if (!password) throw new Error("Password required to unlock keys");
      }
      // Get private keys from IndexedDB
      const ed25519Priv = await getKeyFromIndexedDB(`${username}_ed25519_priv`, password);
      const mldsaPriv = await getKeyFromIndexedDB(`${username}_mldsa_priv`, password);
      const x25519Priv = await getKeyFromIndexedDB(`${username}_x25519_priv`, password);
      if (!ed25519Priv || !mldsaPriv || !x25519Priv) throw new Error("Could not load your private keys. Please log in again.");
      // Compose privateKeyBundle for uploadFile
      const privateKeyBundle = {
        preQuantum: {
          identityKem: { privateKey: x25519Priv },
          identitySigning: { privateKey: ed25519Priv },
        },
        postQuantum: {
          identitySigning: { privateKey: mldsaPriv },
        },
      };
      // Upload
      const result = await uploadFile(
        fileContent,
        metadata,
        username,
        privateKeyBundle,
        ""
      );
      if (!result.success) throw new Error(result.error || "Upload failed");
      // Save client_data to IndexedDB for decryption
      if (result.fileId && result.clientData) {
        try {
          console.log(`[DriveMain][Upload] Saving clientData to IndexedDB for fileId=${result.fileId}:`, result.clientData);
          await saveObjectToIndexedDB(
            result.fileId.toString(),
            result.clientData
          );
          console.log(`[DriveMain][Upload] Successfully saved clientData to IndexedDB for fileId=${result.fileId}`);
        } catch (e) {
          console.error(`[DriveMain][Upload] Failed to save clientData to IndexedDB for fileId=${result.fileId}:`, e);
        }
      } else {
        console.warn(`[DriveMain][Upload] No clientData or fileId to save to IndexedDB. result=`, result);
      }
      setPage(1);
    } catch (err) {
      setUploadError((err as Error).message);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const getFileIcon = (fileType: string) => {
    switch (fileType) {
      case "image": return <span role="img" aria-label="image">🖼️</span>;
      case "document": case "pdf": return <span role="img" aria-label="doc">📄</span>;
      case "audio": return <span role="img" aria-label="audio">🎵</span>;
      case "video": return <span role="img" aria-label="video">🎬</span>;
      default: return <span role="img" aria-label="file">📁</span>;
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {isLoading && (
        <div className="flex items-center justify-center p-4">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white"></div>
          <span className="ml-2">Loading files...</span>
        </div>
      )}
      <header className="border-b border-gray-800 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/60">
        <div className="flex h-16 items-center px-6">
          <div className="flex flex-1 items-center space-x-4">
            <h1 className="text-xl font-semibold text-white">Drive</h1>
            <div className="flex-1 max-w-md">
              <Input type="search" placeholder="Search files..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="bg-gray-800 border-gray-700" />
            </div>
          </div>
          <Button onClick={handleUpload} className="bg-blue-600 hover:bg-blue-700">Upload</Button>
          <button onClick={() => { localStorage.removeItem("drive_username"); localStorage.removeItem("drive_password"); window.location.reload(); }} className="ml-4 px-4 py-2 bg-red-600 hover:bg-red-700 rounded text-white">Logout</button>
          <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileInputChange} />
        </div>
      </header>
      <main className="p-6">
        {uploading && (
          <div className="mb-4 text-blue-400">Uploading file...</div>
        )}
        {uploadError && (
          <div className="mb-4 text-red-400">Upload error: {uploadError}</div>
        )}
        <div className="space-y-4">
          <DriveList
            items={filteredItems}
            onFolderClick={() => {}}
            getFileIcon={getFileIcon}
            onDelete={handleDelete}
            onRename={(item) => handleRename(item)}
            onFileOpen={handleFileOpen}
            setPage={setPage}
            page={page}
            hasNextPage={hasNextPage}
          />
        </div>
      </main>
    </div>
  );
}
