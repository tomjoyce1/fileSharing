import React, { useState, useRef } from "react";
import DriveList from "@/components/DriveList";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useDriveFiles } from "./useDriveFiles";
import { useFileUpload } from "./useFileUpload";
import { useFileActions } from "./useFileActions";
import { useKeyValidation } from "./useKeyValidation";
import type { FileItem, DriveItem } from "./driveTypes";

export default function DriveMain() {
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { files, hasNextPage, fetchFiles } = useDriveFiles(page, setError, setIsLoading);
  const { handleFileChange } = useFileUpload(fetchFiles, page, setError, setIsLoading);
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
          <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
        </div>
      </header>
      <main className="p-6">
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
