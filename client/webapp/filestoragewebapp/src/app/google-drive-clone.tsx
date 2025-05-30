"use client";

import { useState, useRef, useEffect } from "react";
import {
  ChevronRight,
  Upload,
  ImageIcon,
  FileText,
  Music,
  Video,
  File,
} from "lucide-react";
import { getKeyFromIndexedDB, decryptPrivateKey } from "../lib/crypto/KeyUtils";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { mockData } from "./mockdata";
import type { FileItem, FolderItem, DriveItem } from "./mockdata";
import DriveList from "../components/DriveList";
import {
  generateFEKComponents,
  deriveFEK,
  encryptFileBuffer,
  encryptMetadataWithFEK,
  signFileRecordEd25519,
  decryptFileBuffer,
} from "~/lib/crypto/encryptor";
import sodium from "libsodium-wrappers";

export default function GoogleDriveClone() {
  const [currentPath, setCurrentPath] = useState<string[]>(["root"]);
  const [searchQuery, setSearchQuery] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [, forceUpdate] = useState({});

  const sodiumReady: Promise<void> = (
    sodium as typeof import("libsodium-wrappers")
  ).ready;

  useEffect(() => {
    void (async () => {
      await sodiumReady;
    })();
  }, [sodiumReady]);

  const getCurrentFolder = (): FolderItem => {
    let current: FolderItem | FileItem | undefined = mockData.root;
    for (let i = 1; i < currentPath.length; i++) {
      const pathSegment = currentPath[i];
      if (current && current.type === "folder") {
        current = current.children.find((item) => item.id === pathSegment);
      }
    }
    if (!current || current.type !== "folder") return mockData.root;
    return current;
  };

  const handleFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      if (!e.target?.result) return;
      await sodiumReady;

      const arrayBuffer = e.target.result as ArrayBuffer;
      const fileId = file.name + Date.now();

      const { s_pre, s_post } = await generateFEKComponents();
      const fek = await deriveFEK(s_pre, s_post);
      const { encryptedData, nonce } = await encryptFileBuffer(
        fek,
        arrayBuffer,
      );
      const blob = new Blob([encryptedData], { type: file.type });
      const fileUrl = URL.createObjectURL(blob);

      const fileType: FileItem["fileType"] = file.type.startsWith("image")
        ? "image"
        : file.type.startsWith("audio")
          ? "audio"
          : file.type.startsWith("video")
            ? "video"
            : file.type === "application/pdf"
              ? "pdf"
              : "document";

      // Save components
      localStorage.setItem(
        `fek_${fileId}_s_pre`,
        JSON.stringify(Array.from(s_pre)),
      );
      localStorage.setItem(
        `fek_${fileId}_s_post`,
        JSON.stringify(Array.from(s_post)),
      );
      localStorage.setItem(
        `fek_${fileId}_nonce`,
        JSON.stringify(Array.from(nonce)),
      );

      const metadata = {
        original_filename: file.name,
        file_size_bytes: file.size,
        file_type: file.type,
        content_hash: Array.from(
          new Uint8Array(await crypto.subtle.digest("SHA-256", encryptedData)),
        ),
      };

      const { encryptedMetadata, nonce: metadataNonce } =
        await encryptMetadataWithFEK(fek, metadata);
      localStorage.setItem(
        `fek_${fileId}_metadata`,
        JSON.stringify(Array.from(encryptedMetadata)),
      );
      localStorage.setItem(
        `fek_${fileId}_metadata_nonce`,
        JSON.stringify(Array.from(metadataNonce)),
      );

      try {
        const username = localStorage.getItem("drive_username") ?? "alice";
        const edRaw = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
        if (!edRaw)
          throw new Error("No Ed25519 key found. Please log in again.");

        const edSalt = edRaw.slice(0, 16);
        const edIv = edRaw.slice(16, 28);
        const edCipher = edRaw.slice(28);

        let password = localStorage.getItem("drive_password");
        if (!password) {
          password = prompt("Enter your password to unlock your key:") ?? "";
          localStorage.setItem("drive_password", password);
        }

        const decrypted = await decryptPrivateKey(
          edCipher,
          password,
          edSalt,
          edIv,
        );
        const keypair = {
          publicKey: new Uint8Array([]), // not used in signing
          privateKey: decrypted,
        };

        await signFileRecordEd25519(
          fileId,
          username,
          fileUrl,
          encryptedMetadata,
          keypair.privateKey,
        );
      } catch (err) {
        console.error("Error signing file:", err);
        alert("Signature failed. Please re-authenticate.");
      }

      const newFile: FileItem = {
        id: fileId,
        name: file.name,
        type: "file",
        fileType,
        size: `${(file.size / (1024 * 1024)).toFixed(1)} MB`,
        modified: "just now",
        url: fileUrl,
        encrypted: true,
        nonce,
      };

      const folder = getCurrentFolder();
      folder.children.push(newFile);
      forceUpdate({});
    };

    reader.readAsArrayBuffer(file);
  };

  const handleUpload = () => fileInputRef.current?.click();

  const navigateToFolder = (folderId: string) => {
    setCurrentPath([...currentPath, folderId]);
  };

  const navigateToBreadcrumb = (index: number) => {
    setCurrentPath(currentPath.slice(0, index + 1));
  };

  const getBreadcrumbNames = (): string[] => {
    const names = ["My Drive"];
    let current: FolderItem | FileItem | undefined = mockData.root;
    for (let i = 1; i < currentPath.length; i++) {
      const pathSegment = currentPath[i];
      if (current && current.type === "folder") {
        current = current.children.find((item) => item.id === pathSegment);
        if (current) names.push(current.name);
      }
    }
    return names;
  };

  const breadcrumbNames = getBreadcrumbNames();

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

  const handleDelete = (item: DriveItem) => {
    const folder = getCurrentFolder();
    if (folder.type !== "folder") return;
    const index = folder.children.findIndex((child) => child.id === item.id);
    if (index !== -1) {
      if (item.type === "file" && item.url?.startsWith("blob:")) {
        URL.revokeObjectURL(item.url);
      }
      folder.children.splice(index, 1);
      forceUpdate({});
    }
  };

  const handleRename = (item: DriveItem): DriveItem => {
    const newName = prompt("Enter new name", item.name);
    if (newName && newName !== item.name) {
      item.name = newName;
      forceUpdate({});
    }
    return item;
  };

  const handleFileOpen = async (file: FileItem) => {
    if (!file.encrypted || !file.url) {
      window.open(file.url, "_blank");
      return;
    }

    const response = await fetch(file.url);
    const encryptedArrayBuffer = await response.arrayBuffer();

    const s_pre = new Uint8Array(
      JSON.parse(
        localStorage.getItem(`fek_${file.id}_s_pre`) ?? "[]",
      ) as number[],
    );
    const s_post = new Uint8Array(
      JSON.parse(
        localStorage.getItem(`fek_${file.id}_s_post`) ?? "[]",
      ) as number[],
    );
    const nonce = new Uint8Array(
      JSON.parse(
        localStorage.getItem(`fek_${file.id}_nonce`) ?? "[]",
      ) as number[],
    );
    const fek = await deriveFEK(s_pre, s_post);

    const decryptedBuffer = await decryptFileBuffer(
      fek,
      encryptedArrayBuffer,
      nonce,
    );
    const blob = new Blob([decryptedBuffer]);
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  };

  const currentFolder = getCurrentFolder();
  const filteredItems =
    currentFolder.type === "folder"
      ? currentFolder.children.filter((item) =>
          item.name.toLowerCase().includes(searchQuery.toLowerCase()),
        )
      : [];

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/60">
        <div className="flex h-16 items-center px-6">
          <div className="flex flex-1 items-center space-x-4">
            <h1 className="text-xl font-semibold text-white">Drive</h1>
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
          <Button
            onClick={handleUpload}
            className="bg-blue-600 hover:bg-blue-700"
          >
            <Upload className="mr-2 h-4 w-4" /> Upload
          </Button>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
          />
        </div>
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
      <main className="p-6">
        <div className="space-y-4">
          <DriveList
            items={filteredItems}
            onFolderClick={navigateToFolder}
            getFileIcon={getFileIcon}
            onDelete={handleDelete}
            onRename={handleRename}
            onFileOpen={handleFileOpen}
          />
        </div>
      </main>
    </div>
  );
}
