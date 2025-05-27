// component for rendering the list

import {
  Folder,
  Download,
  Share,
  Trash2,
  FolderPen,
  MoreVertical,
  File,
  ImageIcon,
  FileText,
  Music,
  Video,
} from "lucide-react";
import { Button } from "~/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "~/components/ui/dropdown-menu";
import type { FileItem, FolderItem, DriveItem } from "./mockData";

type Props = {
  items: DriveItem[];
  onFolderClick: (id: string, name: string) => void;
  getFileIcon: (fileType: string) => React.ReactNode;
};

export default function DriveList({
  items,
  onFolderClick,
  getFileIcon,
}: Props) {
  return (
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
        {items.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            This folder is empty
          </div>
        ) : (
          items.map((item) => (
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
                    onClick={() => onFolderClick(item.id, item.name)}
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
                      <DropdownMenuItem className="text-white" asChild>
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
                    <DropdownMenuItem className="text-white">
                      {" "}
                      <Share className="mr-2 h-4 w-4" />
                      Share
                    </DropdownMenuItem>

                    <DropdownMenuItem className="text-white">
                      {" "}
                      <FolderPen className="mr-2 h-4 w-4" />
                      Rename
                    </DropdownMenuItem>

                    <DropdownMenuItem className="text-red-400">
                      <Trash2 className="mr-2 h-4 w-4" />
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
  );
}
