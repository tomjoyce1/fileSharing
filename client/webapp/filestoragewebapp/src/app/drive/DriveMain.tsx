import React, { useState, useRef } from "react";
import DriveList from "@/components/DriveList";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useDriveFiles } from "./useDriveFiles";
import { useFileActions } from "./useFileActions";
import { useKeyValidation } from "./useKeyValidation";
import type { FileItem, DriveItem } from "./driveTypes";
import { uploadFile } from "./utils/encryption";
import { getKeyFromIndexedDB } from "@/lib/crypto/KeyUtils";

export default function DriveMain() {
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const { files, hasNextPage, fetchFiles } = useDriveFiles(page, setError, setIsLoading);

  const { handleDelete, handleRename, handleFileOpen, decryptMetadata, ensureFileItem } = useFileActions(fetchFiles, page, setError, setIsLoading);

  // Key validation on mount
  useKeyValidation(page, setError, fetchFiles);

  // Processed files for display
  const [processedFiles, setProcessedFiles] = useState<FileItem[]>([]);
  React.useEffect(() => {
    const processFiles = async () => {
      const processed = await Promise.all(
        files.map(async (file) => {
          const metadata = await decryptMetadata(file);
          let fileType: FileItem["fileType"] = 'document';
          if (metadata.file_type.startsWith('image')) fileType = 'image';
          else if (metadata.file_type.startsWith('audio')) fileType = 'audio';
          else if (metadata.file_type.startsWith('video')) fileType = 'video';
          else if (metadata.file_type === 'application/pdf') fileType = 'pdf';
          return {
            id: file.id?.toString() ?? file.file_id?.toString() ?? '',
            name: metadata.original_filename,
            type: 'file' as const,
            fileType,
            size: `${(metadata.file_size_bytes / (1024 * 1024)).toFixed(1)} MB`,
            modified: file.upload_timestamp
              ? new Date(file.upload_timestamp * 1000).toLocaleDateString()
              : '-',
            url: `/api/fs/download/${file.id ?? file.file_id}`,
            encrypted: true
          };
        })
      );
      setProcessedFiles(processed);
    };
    void processFiles();
  }, [files]);

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
      // Get userId (not available in localStorage, so use 1 as placeholder or fetch from server if needed)
      const userId = 1;
      // Upload
      const result = await uploadFile(
        fileContent,
        metadata,
        userId,
        username,
        privateKeyBundle,
        ""
      );
      if (!result.success) throw new Error(result.error || "Upload failed");
      // Refresh file list
      await fetchFiles(page);
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
            onRename={handleRename}
            onFileOpen={handleFileOpen}
          />
          {hasNextPage && (
            <div className="text-center mt-4">
              <Button onClick={() => setPage(p => p + 1)} variant="outline">Load More</Button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
