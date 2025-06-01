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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import DriveList from "@/components/DriveList";
import {
  generateFEKComponents,
  deriveFEK,
  encryptFileBuffer,
  encryptMetadataWithFEK,
  deriveMEK,
  decryptFileBuffer,
  decryptMetadataWithMEK,
  encryptWithKey,
  FILE_KEY_SIZE,
  NONCE_SIZE,
  type EncryptionResult
} from "@/lib/crypto/encryptor";
import {
  storeEncryptionKeys,
  signFileRecord,
  getKeyFromIndexedDB,
  getEncryptionKeys,
  getPrivateKeyFromIndexedDB
} from "@/lib/crypto/KeyUtils";
import type { FileMetadataListItem } from "@/lib/types";
import sodium from "libsodium-wrappers";
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
// import scyrpt noble hashes scrypt
interface FileItem {
  id: string;
  name: string;
  type: "file";
  fileType: "image" | "document" | "audio" | "video" | "pdf";
  size: string;
  modified: string;
  url?: string;
  encrypted?: boolean;
  nonce?: Uint8Array;
}

interface FileMetadata {
  original_filename: string;
  file_size_bytes: number;
  file_type: string;
}

type DriveItem = FileItem;

export default function GoogleDriveClone() {
  const [currentPath, setCurrentPath] = useState<string[]>(["root"]);
  const [searchQuery, setSearchQuery] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [, forceUpdate] = useState({});

  const [files, setFiles] = useState<FileMetadataListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [hasNextPage, setHasNextPage] = useState(false);

  const sodiumReady: Promise<void> = (
    sodium as typeof import("libsodium-wrappers")
  ).ready;

  useEffect(() => {
    void (async () => {
      await sodiumReady;
    })();
  }, [sodiumReady]);

  // Helper: List all keys in IndexedDB for debugging
  async function listAllIndexedDBKeys() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open("DriveKeysDB", 1);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction("keys", "readonly");
        const store = tx.objectStore("keys");
        const keys: string[] = [];
        const cursorRequest = store.openCursor();
        cursorRequest.onsuccess = (event) => {
          const cursor = (event as any).target.result;
          if (cursor) {
            keys.push(cursor.key);
            cursor.continue();
          } else {
            resolve(keys);
          }
        };
        cursorRequest.onerror = () => reject(cursorRequest.error);
      };
      request.onerror = () => reject(request.error);
    });
  }

  // Async initialization to verify keys on mount
  // Modified verifyKeys useEffect in GoogleDriveClone
useEffect(() => {
  const verifyKeys = async () => {
    await new Promise(resolve => setTimeout(resolve, 100)); // Allow localStorage propagation
    const username = localStorage.getItem("drive_username")?.trim();
    
    if (!username) {
      console.error('[Key Verification] No username in localStorage');
      return;
    }

    // New transaction-aware verification
    const verifyTransaction = async () => {
      const db = await new Promise<IDBDatabase>(resolve => {
        const req = indexedDB.open("DriveKeysDB", 1);
        req.onsuccess = () => resolve(req.result);
      });

      const tx = db.transaction("keys", "readonly");
      await new Promise(resolve => (tx.oncomplete = resolve));
      
      const keys = await Promise.all([
        getKeyFromIndexedDB(`${username}_ed25519_priv`),
        getKeyFromIndexedDB(`${username}_x25519_priv`),
        getKeyFromIndexedDB(`${username}_mldsa_priv`)
      ]);

      keys.forEach((k, i) => {
        if (!k || k.length < 28) { // Verify minimum encrypted data length
          console.error(`[Key Verification] Invalid key ${i}:`, k, {
            typeofKey: typeof k,
            key: k,
            keyLength: k ? k.length : null,
            keyIndex: i,
            username,
            keyName: [
              `${username}_ed25519_priv`,
              `${username}_x25519_priv`,
              `${username}_mldsa_priv`
            ][i]
          });
          throw new Error(`Key ${i} validation failed`);
        }
      });
    };

    try {
      await verifyTransaction();
      console.log('[Key Verification] All keys validated successfully');
    } catch (err) {
      console.error('[Key Verification] Key validation failed:', err);
      localStorage.removeItem("drive_username");

    }
  };

  verifyKeys();
}, []);
// import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
// import sodium from "libsodium-wrappers";

// Helper to convert Uint8Array to hex string
const toHex = (u8: Uint8Array): string =>
  Array.from(u8)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

// Helper to base64 decode string to Uint8Array
const base64ToUint8Array = (b64: string): Uint8Array =>
  Uint8Array.from(atob(b64), c => c.charCodeAt(0));

const getSignatureHeaders = async (
  owner_user_id: number,
  file_content_base64: string,
  metadata_base64: string,
  username: string
) => {
  await sodium.ready;

  // Get keys from IndexedDB - fix key name formatting
  const edKeyName = `${username}_ed25519_priv`;
  const mldsaKeyName = `${username}_mldsa_priv`;

  console.log('[Debug] Getting Ed25519 key:', {
    keyName: edKeyName,
    username
  });

  const edPrivateKey = await getPrivateKeyFromIndexedDB(edKeyName);
  if (!edPrivateKey || !(edPrivateKey instanceof Uint8Array) || edPrivateKey.length !== 64) {
    throw new Error("Invalid Ed25519 key found in IndexedDB. Please log out and re-register.");
  }

  console.log('[Debug] Getting ML-DSA key:', {
    keyName: mldsaKeyName,
    username
  });

  const mldsaPrivateKey = await getPrivateKeyFromIndexedDB(mldsaKeyName);
  if (!mldsaPrivateKey || !(mldsaPrivateKey instanceof Uint8Array)) {
    throw new Error("No ML-DSA-87 key found in IndexedDB. Please log in again.");
  }

  // Step 1: Hash the file content and metadata (decoded from base64)
  const fileBytes = base64ToUint8Array(file_content_base64);
  const metadataBytes = base64ToUint8Array(metadata_base64);

  // SHA-256 digest using Web Crypto API
  const fileHashBuffer = await crypto.subtle.digest("SHA-256", fileBytes);
  const metadataHashBuffer = await crypto.subtle.digest("SHA-256", metadataBytes);

  const fileHashHex = toHex(new Uint8Array(fileHashBuffer));
  const metadataHashHex = toHex(new Uint8Array(metadataHashBuffer));

  // Step 2: Create signature message string exactly like server
  // Format: owner_user_id|fileHashHex|metadataHashHex
  const messageString = `${owner_user_id}|${fileHashHex}|${metadataHashHex}`;

  // Step 3: Encode string as UTF-8 bytes for signing
  const encoder = new TextEncoder();
  const messageToSign = encoder.encode(messageString);

  // Step 4: Sign with Ed25519 (libsodium)
  const preQuantumSignature = sodium.crypto_sign_detached(messageToSign, edPrivateKey);

  // Step 5: Sign with ML-DSA (noble library)
  const postQuantumSignature = ml_dsa87.sign(messageToSign, mldsaPrivateKey);

  // Step 6: Return headers with signatures and metadata
  const timestamp = Date.now().toString();
  const toBase64 = (u8: Uint8Array) => btoa(String.fromCharCode(...u8));

  // Step 7: Create headers object
  const headers = {
    'X-Username': username,
    'X-Timestamp': timestamp,
    'X-Signature-PreQuantum': toBase64(preQuantumSignature),
    'X-Signature-PostQuantum': toBase64(postQuantumSignature)
  };

  // Debug log the headers
  console.log('=== Signature Headers ===');
  console.log('Username:', headers['X-Username']);
  console.log('Timestamp:', headers['X-Timestamp']);
  console.log('Pre-Quantum Signature:', headers['X-Signature-PreQuantum']);
  console.log('Post-Quantum Signature:', headers['X-Signature-PostQuantum']);
  console.log('=====================');

  return headers;
};


  const fetchFiles = async (pageNumber: number) => {
    const username = localStorage.getItem("drive_username");
    if (!username) {
      window.location.href = '/auth';
      return;
    }
    try {
      setIsLoading(true);
      setError(null);

      const message = JSON.stringify({ page: pageNumber });
      
      // Get Ed25519 private key
      const edPrivateKey = await getPrivateKeyFromIndexedDB(`${username}_ed25519_priv`);
      if (!edPrivateKey) {
        setError("Your login keys are not available yet. Please wait a moment and click Retry.");
        setIsLoading(false);
        return;
      }
      
      // Get ML-DSA-87 private key
      const mldsaKey = await getPrivateKeyFromIndexedDB(`${username}_mldsa_priv`);
      if (!mldsaKey) {
        setError("Your login keys are not available yet. Please wait a moment and click Retry.");
        setIsLoading(false);
        return;
      }
      
      // Prepare data to sign
      const dataToSign = new Uint8Array([
        ...new TextEncoder().encode(username),
        ...new TextEncoder().encode(message)
      ]);
      
      await sodium.ready;
      
      // Sign with both algorithms
      const preQuantumSignature = sodium.crypto_sign_detached(dataToSign, edPrivateKey);
      const postQuantumSignature = ml_dsa87.sign(dataToSign, mldsaKey);
      
      // Format signatures as required by server
      const timestamp = Date.now().toString();
      const headers = {
        'Content-Type': 'application/json',
        'X-Username': username,
        'X-Timestamp': timestamp,
        // Combine signatures as expected by server's NetworkingHelper
        'X-Signature': `${Buffer.from(preQuantumSignature).toString('base64')}.${Buffer.from(postQuantumSignature).toString('base64')}`
      };

      const response = await fetch("/api/fs/list", {
        method: "POST",
        headers,
        body: message,
      });

      if (response.status === 401) {
        window.location.href = '/auth';
        return;
      }

      if (!response.ok) {
        throw new Error("Failed to fetch files");
      }

      const { fileData, hasNextPage } = await response.json();
      setFiles(fileData);
      setHasNextPage(hasNextPage);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch files");
      setFiles([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void fetchFiles(page);
  }, [page]);
const handleFileChange = async (
  event: React.ChangeEvent<HTMLInputElement>
) => {
  const file = event.target.files?.[0];
  if (!file) return;

  setIsLoading(true);
  setError(null);

  try {
    await sodiumReady;
    const owner_user_id = crypto.randomUUID();

    // Step 1: Generate encryption components
    const { s_pre, s_post } = await generateFEKComponents();
    const fek = await deriveFEK(s_pre, s_post);

    // Step 2: Read and encrypt file buffer
    const fileBuffer = await file.arrayBuffer();
    const { encryptedData, nonce: fileNonce } = await encryptFileBuffer(fek, fileBuffer);

    // Step 3: Build metadata object
    const contentHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encryptedData)
    );
    const metadata = {
      original_filename: file.name,
      file_size_bytes: file.size,
      file_type: file.type,
      content_hash: Array.from(contentHash),
      upload_time: new Date().toISOString()
    };

    // Step 4: Encrypt metadata
    const { encryptedData: encryptedMetadata, nonce: metadataNonce } =
      await encryptMetadataWithFEK(fek, metadata);

    // Debug logging
    console.debug('Encrypted file length:', encryptedData.byteLength);
    console.debug('Encrypted metadata length:', encryptedMetadata.byteLength);

    if (!(encryptedData instanceof Uint8Array) || !(encryptedMetadata instanceof Uint8Array)) {
      throw new Error('Encryption functions returned invalid output');
    }

    // Step 5: Store key components
    await storeEncryptionKeys(owner_user_id, {
      s_pre: Array.from(s_pre),
      s_post: Array.from(s_post),
      file_nonce: Array.from(fileNonce),
      metadata_nonce: Array.from(metadataNonce)
    });

    // Get username from localStorage
    const username = localStorage.getItem("drive_username");
    if (!username) {
      throw new Error("You are not logged in. Please log in again.");
    }

    // Convert encrypted data to base64
    const file_content_base64 = btoa(String.fromCharCode.apply(null, Array.from(encryptedData)));
    const metadata_base64 = btoa(String.fromCharCode.apply(null, Array.from(encryptedMetadata)));

    // Step 6: Get signature headers
    let headers;
    try {
      headers = await getSignatureHeaders(
        owner_user_id,
        file_content_base64,
        metadata_base64,
        username
      );
    } catch (e: any) {
      console.error('Failed to generate signature headers:', e);
      throw new Error(e?.message || 'Failed to generate signature headers');
    }

    // Step 7: Create FormData
    const formData = new FormData();
    formData.append('file', new Blob([encryptedData], { type: 'application/octet-stream' }));
    formData.append('fileId', owner_user_id);
    formData.append('metadata', new Blob([encryptedMetadata], { type: 'application/octet-stream' }));
    formData.append('metadataNonce', new Blob([metadataNonce]));

    // Step 8: Upload file
    const response = await fetch('/api/fs/upload', {
      method: 'POST',
      body: formData,
      headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Upload failed: ${errorText}`);
    }

    // Step 9: Refresh file list
    await fetchFiles(page);
  } catch (err) {
    console.error('Error uploading file:', err);
    setError(err instanceof Error ? err.message : 'Failed to upload file');
  } finally {
    setIsLoading(false);
    if (event.target) {
      event.target.value = '';
    }
  }
};

  const handleUpload = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const navigateToFolder = () => {}; // Not used in this version

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
    const fileItem = ensureFileItem(item);
    void (async () => {
      try {
        const response = await fetch(`/api/fs/delete/${fileItem.id}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          }
        });

        if (!response.ok) {
          throw new Error('Failed to delete file');
        }

        void fetchFiles(page);
      } catch (err) {
        console.error('Error deleting file:', err);
        alert('Failed to delete file');
      }
    })();
  };

  const handleRename = (item: DriveItem): FileItem => {
    const fileItem = ensureFileItem(item);
    const newName = prompt("Enter new name", fileItem.name);
    if (!newName || newName === fileItem.name) {
      return fileItem;
    }

    void (async () => {
      try {
        const response = await fetch(`/api/fs/rename/${fileItem.id}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ newName })
        });

        if (!response.ok) {
          throw new Error('Failed to rename file');
        }

        void fetchFiles(page);
      } catch (err) {
        console.error('Error renaming file:', err);
        alert('Failed to rename file');
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

    // Fix: convert ArrayBuffer to Uint8Array
    const decryptedBuffer = await decryptFileBuffer(
      fek,
      new Uint8Array(encryptedArrayBuffer),
      nonce,
    );
    const blob = new Blob([decryptedBuffer]);
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  };

  const decryptMetadata = async (file: FileMetadataListItem): Promise<FileMetadata> => {
    try {
      // You need to get the correct MEK and nonce for this file
      // This example assumes you have a getEncryptionKeys helper
      const keys = await getEncryptionKeys(file.id);
      if (!keys) throw new Error('Missing encryption keys');
      const s_pre = new Uint8Array(keys.s_pre);
      const s_post = new Uint8Array(keys.s_post);
      const fek = await deriveFEK(s_pre, s_post);
      const mek = await deriveMEK(fek);
      const metadataNonce = new Uint8Array(keys.metadata_nonce);
      // file.metadata is likely a Uint8Array or base64 string
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
      console.error('Failed to decrypt metadata:', err);
      return {
        original_filename: 'Unknown File',
        file_size_bytes: 0,
        file_type: 'application/octet-stream'
      };
    }
  };

  const [processedFiles, setProcessedFiles] = useState<FileItem[]>([]);

  useEffect(() => {
    const processFiles = async () => {
      const processed = await Promise.all(
        files.map(async (file) => {
          const metadata = await decryptMetadata(file);
          return {
            id: file.id.toString(),
            name: metadata.original_filename,
            type: 'file' as const,
            fileType: metadata.file_type.startsWith('image') ? 'image'
              : metadata.file_type.startsWith('audio') ? 'audio'
              : metadata.file_type.startsWith('video') ? 'video'
              : metadata.file_type === 'application/pdf' ? 'pdf'
              : 'document',
            size: `${(metadata.file_size_bytes / (1024 * 1024)).toFixed(1)} MB`,
            modified: new Date((file.upload_timestamp || 0) * 1000).toLocaleDateString(),
            url: `/api/fs/download/${file.id}`,
            encrypted: true
          } as const;
        })
      );
      setProcessedFiles(processed);
    };

    void processFiles();
  }, [files]);

  const filteredItems = processedFiles.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const ensureFileItem = (item: DriveItem): FileItem => {
    if (item.type !== "file") {
      throw new Error("Expected file item");
    }
    return item;
  };

  const downloadFile = async (file: FileMetadataListItem) => {
    try {
      setIsLoading(true);
      
      // Get encryption keys from storage
      const keys = await getEncryptionKeys(file.id);
      if (!keys) {
        throw new Error('Encryption keys not found');
      }

      // Convert stored arrays back to Uint8Arrays
      const s_pre = new Uint8Array(keys.s_pre);
      const s_post = new Uint8Array(keys.s_post);
      const fileNonce = new Uint8Array(keys.file_nonce);
      const metadataNonce = new Uint8Array(keys.metadata_nonce);

      // Derive encryption keys
      const fek = await deriveFEK(s_pre, s_post);
      const mek = await deriveMEK(fek);

      // Download encrypted file
      const response = await fetch(`/api/fs/download/${file.id}`);
      if (!response.ok) {
        throw new Error('Failed to download file');
      }
      
      // Get the encrypted file data
      const encryptedData = new Uint8Array(await response.arrayBuffer());
      
      // Decrypt file and metadata
      const decryptedBuffer = await decryptFileBuffer(fek, encryptedData, fileNonce);
      const metadata = await decryptMetadataWithMEK(mek, file.metadata as Uint8Array, metadataNonce);

      // Create blob and download
      const blob = new Blob([new Uint8Array(decryptedBuffer)], { 
        type: metadata.file_type || 'application/octet-stream' 
      });
      const url = URL.createObjectURL(blob);
      
      // Create download link and click it
      const a = document.createElement('a');
      a.href = url;
      a.download = metadata.original_filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

    } catch (err) {
      console.error('Error downloading file:', err);
      setError(err instanceof Error ? err.message : 'Failed to download file');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/60">
        <div className="flex h-16 items-center px-6">
          <div className="flex flex-1 items-center space-x-4">
            <h1 className="text-xl font-semibold text-white">Drive</h1>
            <div className="flex-1 max-w-md">
              <Input
                type="search"
                placeholder="Search files..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-gray-800 border-gray-700"
              />
            </div>
          </div>
          <Button onClick={handleUpload} className="bg-blue-600 hover:bg-blue-700">
            <Upload className="mr-2 h-4 w-4" /> Upload
          </Button>
          
          <button
            onClick={() => {
              localStorage.removeItem("drive_username");
              localStorage.removeItem("drive_password");
              window.location.reload();
            }}
            className="ml-4 px-4 py-2 bg-red-600 hover:bg-red-700 rounded text-white"
          >
            Logout
          </button>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
          />
        </div>
      </header>

      
      <main className="p-6">
        <div className="space-y-4">
          {isLoading ? (
            <div className="text-center p-8">
              <div className="animate-spin h-8 w-8 border-4 border-blue-500 border-t-transparent rounded-full mx-auto mb-4"></div>
              <p className="text-gray-400">Loading files...</p>
            </div>
          ) : error ? (
            <div className="text-center p-8 text-red-400">
              <p>{error}</p>
              <Button onClick={async () => {
                setError(null);
                setIsLoading(true);
                await fetchFiles(page);
                setIsLoading(false);
              }} className="mt-4">
                Retry
              </Button>
              <Button onClick={() => {
                localStorage.removeItem("drive_username");
                localStorage.removeItem("drive_password");
                window.location.href = '/auth';
              }} className="mt-4 ml-2" variant="destructive">
                Reset Login
              </Button>
            </div>
          ) : (
            <>
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
                  <Button onClick={() => setPage(p => p + 1)} variant="outline">
                    Load More
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}
