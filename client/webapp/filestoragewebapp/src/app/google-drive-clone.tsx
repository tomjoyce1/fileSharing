"use client";
// main homepage and layout
import { useState, useRef } from "react";
import {
  ChevronRight,
  Upload,
  ImageIcon,
  FileText,
  Music,
  Video,
  File,
} from "lucide-react";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { mockData, FileItem, FolderItem, DriveItem } from "./mockdata";
import DriveList from "../components/DriveList";

export default function GoogleDriveClone() {
  const [currentPath, setCurrentPath] = useState<string[]>(["root"]);
  const [searchQuery, setSearchQuery] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [, forceUpdate] = useState({});

  // Get current folder based on path
  const getCurrentFolder = (): FolderItem => {
    let current: any = mockData.root;
    for (let i = 1; i < currentPath.length; i++) {
      const pathSegment = currentPath[i];
      current = current.children.find(
        (item: DriveItem) => item.id === pathSegment,
      );
    }
    return current;
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];

    const reader = new FileReader();
    if (file) {
      console.log("Selected", file.name);
      reader.onload = async (e) => {
        if (!e.target || !e.target.result) return;
        const arrayBuffer = e.target.result;
        // encrypt with aesgcm
        // 2 - do signing

        // Create a Blob URL for the file contents
        const blob = new Blob([arrayBuffer], { type: file.type });
        const fileUrl = URL.createObjectURL(blob);

        // Infer fileType for your FileItem type
        let fileType: FileItem["fileType"] = "document";
        if (file.type.startsWith("image")) fileType = "image";
        else if (file.type.startsWith("audio")) fileType = "audio";
        else if (file.type.startsWith("video")) fileType = "video";
        else if (file.type === "application/pdf") fileType = "pdf";

        const newFile: FileItem = {
          id: file.name + Date.now(),
          name: file.name,
          type: "file",
          fileType,
          size: `${(file.size / (1024 * 1024)).toFixed(1)} MB`,
          modified: "just now",
          url: fileUrl,
        };

        // Add to mockdata
        const folder = getCurrentFolder();
        folder.children.push(newFile);
        forceUpdate({});
      };
      reader.readAsArrayBuffer(file);
    }
  };
  const handleUpload = () => {
    fileInputRef.current?.click();
  };

  const currentFolder = getCurrentFolder();

  // Navigate to folder
  const navigateToFolder = (folderId: string, folderName: string) => {
    setCurrentPath([...currentPath, folderId]);
  };

  // Navigate via breadcrumb
  const navigateToBreadcrumb = (index: number) => {
    setCurrentPath(currentPath.slice(0, index + 1));
  };

  // Get breadcrumb names
  const getBreadcrumbNames = (): string[] => {
    const names = ["My Drive"];
    let current: any = mockData.root;
    for (let i = 1; i < currentPath.length; i++) {
      const pathSegment = currentPath[i];
      current = current.children.find(
        (item: DriveItem) => item.id === pathSegment,
      );
      if (current) {
        names.push(current.name);
      }
    }
    return names;
  };
  const breadcrumbNames = getBreadcrumbNames();

  // Get file icon
  const getFileIcon = (fileType: string) => {
    switch (fileType) {
      case "image":
        return <ImageIcon className="h-4 w-4 text-blue-400" />;
      case "document":
      case "pdf":
        return <FileText className="h-4 w-4 text-red-400" />;
      case "audio":
        return <Music className="h-4 w-4 text-green-400" />;
      case "video":
        return <Video className="h-4 w-4 text-purple-400" />;
      default:
        return <File className="h-4 w-4 text-gray-400" />;
    }
  };

  // Delete handler for DriveList
  const handleDelete = (item: DriveItem) => {
    // Find the current folder
    const folder = getCurrentFolder();
    // Remove the item from the children array
    const index = folder.children.findIndex((child) => child.id === item.id);
    if (index !== -1) {
      // If the file is a blob, revoke the object URL to free memory
      if (item.type === "file" && item.url && item.url.startsWith("blob:")) {
        URL.revokeObjectURL(item.url);
      }
      folder.children.splice(index, 1);
      forceUpdate({});
    }
  };

  // Rename handler for DriveList
  const handleRename = (item: DriveItem) => {
    const newName = prompt("Enter new name", item.name);
    if (newName && newName !== item.name) {
      item.name = newName;
      forceUpdate({});
    }
    return item;
  };

  // Filter items based on search
  const filteredItems = currentFolder.children.filter((item) =>
    item.name.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/60">
        <div className="flex h-16 items-center px-6">
          <div className="flex flex-1 items-center space-x-4">
            <h1 className="text-xl font-semibold text-white">Drive</h1>
            {/* Search */}
            <div className="max-w-md flex-1">
              <Input
                type="search"
                placeholder="Search in Drive"
                className="border-gray-700 bg-gray-800 text-gray-100 placeholder-gray-400"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>
          {/* Upload Button */}
          <Button
            onClick={handleUpload}
            className="bg-blue-600 hover:bg-blue-700"
          >
            <Upload className="mr-2 h-4 w-4" />
            Upload
          </Button>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
          />
        </div>
        {/* Breadcrumbs */}
        <div className="border-t border-gray-800 px-6 py-3">
          <nav className="flex items-center space-x-1 text-sm">
            {breadcrumbNames.map((name, index) => (
              <div key={index} className="flex items-center">
                {index > 0 && (
                  <ChevronRight className="mx-1 h-4 w-4 text-gray-500" />
                )}
                <button
                  onClick={() => navigateToBreadcrumb(index)}
                  className={`rounded px-2 py-1 transition-colors hover:bg-gray-800 ${
                    index === breadcrumbNames.length - 1
                      ? "font-medium text-white"
                      : "text-gray-400 hover:text-gray-200"
                  }`}
                >
                  {name}
                </button>
              </div>
            ))}
          </nav>
        </div>
      </header>
      {/* Main Content */}
      <main className="p-6">
        <div className="space-y-4">
          <DriveList
            items={filteredItems}
            onFolderClick={navigateToFolder}
            getFileIcon={getFileIcon}
            onDelete={handleDelete}
            onRename={handleRename}
          />
        </div>
      </main>
    </div>
  );
}
