"use client";

import { useState, useRef } from "react";
import {
  ChevronRight,
  Upload,
  Folder,
  File,
  ImageIcon,
  FileText,
  Music,
  Video,
  Download,
  MoreVertical,
} from "lucide-react";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "~/components/ui/dropdown-menu";

// Mock data structure
const mockData = {
  root: {
    id: "root",
    name: "My Drive",
    type: "folder" as const,
    children: [
      {
        id: "documents",
        name: "Documents",
        type: "folder" as const,
        children: [
          {
            id: "resume",
            name: "Resume.pdf",
            type: "file" as const,
            fileType: "pdf",
            size: "2.4 MB",
            modified: "2 days ago",
            url: "https://example.com/resume.pdf",
          },
          {
            id: "cover-letter",
            name: "Cover Letter.docx",
            type: "file" as const,
            fileType: "document",
            size: "1.2 MB",
            modified: "1 week ago",
            url: "https://example.com/cover-letter.docx",
          },
        ],
      },
      {
        id: "photos",
        name: "Photos",
        type: "folder" as const,
        children: [
          {
            id: "vacation",
            name: "Vacation",
            type: "folder" as const,
            children: [
              {
                id: "beach1",
                name: "Beach_Photo_1.jpg",
                type: "file" as const,
                fileType: "image",
                size: "5.2 MB",
                modified: "3 days ago",
                url: "https://example.com/beach1.jpg",
              },
              {
                id: "beach2",
                name: "Beach_Photo_2.jpg",
                type: "file" as const,
                fileType: "image",
                size: "4.8 MB",
                modified: "3 days ago",
                url: "https://example.com/beach2.jpg",
              },
            ],
          },
          {
            id: "profile",
            name: "Profile_Picture.png",
            type: "file" as const,
            fileType: "image",
            size: "1.8 MB",
            modified: "1 month ago",
            url: "https://example.com/profile.png",
          },
        ],
      },
      {
        id: "music",
        name: "Music",
        type: "folder" as const,
        children: [
          {
            id: "song1",
            name: "Favorite_Song.mp3",
            type: "file" as const,
            fileType: "audio",
            size: "8.4 MB",
            modified: "2 weeks ago",
            url: "https://example.com/song1.mp3",
          },
        ],
      },
      {
        id: "presentation",
        name: "Project_Presentation.pptx",
        type: "file" as const,
        fileType: "document",
        size: "15.6 MB",
        modified: "5 days ago",
        url: "https://example.com/presentation.pptx",
      },
      {
        id: "video",
        name: "Demo_Video.mp4",
        type: "file" as const,
        fileType: "video",
        size: "125.3 MB",
        modified: "1 week ago",
        url: "https://example.com/demo.mp4",
      },
    ],
  },
};

type FileItem = {
  id: string;
  name: string;
  type: "file";
  fileType: "image" | "document" | "audio" | "video" | "pdf";
  size: string;
  modified: string;
  url: string;
};

type FolderItem = {
  id: string;
  name: string;
  type: "folder";
  children: (FileItem | FolderItem)[];
};

type DriveItem = FileItem | FolderItem;

export default function GoogleDriveClone() {
  const [currentPath, setCurrentPath] = useState<string[]>(["root"]);
  const [searchQuery, setSearchQuery] = useState("");

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

  const fileInputRef = useRef(null);

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      console.log("Selected", file.name);
    }
  };
  const handleUpload = () => {
    alert("Upload functionality would be implemented here!");
    fileInputRef.current?.click();
  };

  const currentFolder = getCurrentFolder();
  const breadcrumbNames = getBreadcrumbNames();

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
          {/* Items List */}
          <div className="rounded-lg border border-gray-700 bg-gray-800">
            {/* List Header */}
            <div className="grid grid-cols-12 gap-4 border-b border-gray-700 p-4 text-sm font-medium text-gray-400">
              <div className="col-span-6">Name</div>
              <div className="col-span-2">Size</div>
              <div className="col-span-3">Modified</div>
              <div className="col-span-1"></div>
            </div>

            {/* Items */}
            <div className="divide-y divide-gray-700">
              {filteredItems.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  {searchQuery
                    ? "No items match your search"
                    : "This folder is empty"}
                </div>
              ) : (
                filteredItems.map((item) => (
                  <div
                    key={item.id}
                    className="hover:bg-gray-750 group grid grid-cols-12 gap-4 p-4 transition-colors"
                  >
                    {/* Name */}
                    <div className="col-span-6 flex items-center space-x-3">
                      {item.type === "folder" ? (
                        <Folder className="h-5 w-5 flex-shrink-0 text-blue-400" />
                      ) : (
                        getFileIcon((item as FileItem).fileType)
                      )}
                      {item.type === "folder" ? (
                        <button
                          onClick={() => navigateToFolder(item.id, item.name)}
                          className="truncate text-left transition-colors hover:text-blue-400"
                        >
                          {item.name}
                        </button>
                      ) : (
                        <a
                          href={(item as FileItem).url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="truncate text-left transition-colors hover:text-blue-400"
                        >
                          {item.name}
                        </a>
                      )}
                    </div>

                    {/* Size */}
                    <div className="col-span-2 flex items-center text-sm text-gray-400">
                      {item.type === "file" ? (item as FileItem).size : "—"}
                    </div>

                    {/* Modified */}
                    <div className="col-span-3 flex items-center text-sm text-gray-400">
                      {item.type === "file" ? (item as FileItem).modified : "—"}
                    </div>

                    {/* Actions */}
                    <div className="col-span-1 flex items-center justify-end">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 p-0 opacity-0 transition-opacity group-hover:opacity-100"
                          >
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent
                          align="end"
                          className="border-gray-700 bg-gray-800"
                        >
                          {item.type === "file" && (
                            <DropdownMenuItem asChild>
                              <a
                                href={(item as FileItem).url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center"
                              >
                                <Download className="mr-2 h-4 w-4" />
                                Download
                              </a>
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem>Share</DropdownMenuItem>
                          <DropdownMenuItem>Rename</DropdownMenuItem>
                          <DropdownMenuItem className="text-red-400">
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
