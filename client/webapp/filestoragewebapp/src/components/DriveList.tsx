// component for rendering the list

import {
  Folder,
  Download,
  Share,
  Trash2,
  FolderPen,
  MoreVertical,
} from "lucide-react";
import { Button } from "~/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "~/components/ui/dropdown-menu";
import { useDriveFiles } from "@/app/drive/useDriveFiles";
import { useEffect, useState } from "react";
import sodium from 'libsodium-wrappers';
import { getObjectFromIndexedDB, getKeyFromIndexedDB } from '@/lib/crypto/KeyUtils';
import { extractX25519RawPublicKeyFromDER } from '@/lib/crypto/KeyHelper';
import { encryptWithSharedSecret } from '@/app/drive/utils/encryption';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { deserializeKeyBundlePublic } from '@/lib/crypto/KeyHelper';
import { createAuthenticatedRequest } from '@/app/drive/utils/encryption';

export interface FileItem {
  id: string;
  name: string;
  type: "file";
  fileType: "image" | "document" | "audio" | "video" | "pdf";
  size: string;
  modified: string;
  url?: string;
}

export type DriveItem = FileItem;

type Props = {
  items: DriveItem[];
  onFolderClick: (id: string, name: string) => void;
  getFileIcon: (fileType: string) => React.ReactNode;
  onDelete: (item: DriveItem) => void;
  onRename: (item: DriveItem) => DriveItem;
  onFileOpen: (file: FileItem) => Promise<void>;
  setPage: (page: number) => void;
  page: number;
  hasNextPage: boolean;
  onShare: (item: DriveItem, recipient: string) => void;
};

async function handleShare(item: DriveItem, recipientUsername: string) {
  if (!recipientUsername || !recipientUsername.trim()) {
    alert('No username entered for sharing.');
    return;
  }
  try {
    // 1. Get client_data for this file (contains fek, mek, nonces)
    const clientData = await getObjectFromIndexedDB(item.id.toString());
    if (!clientData) throw new Error('Missing decryption keys for this file.');

    // 2. Get current user's username and private key bundle
    const username = localStorage.getItem('drive_username') || '';
    let password = localStorage.getItem('drive_password') || '';
    if (!password) {
      password = window.prompt('Enter your password to unlock your keys:') || '';
      if (!password) throw new Error('Password required to unlock keys');
    }
    const ed25519Priv = await getKeyFromIndexedDB(`${username}_ed25519_priv`, password);
    const mldsaPriv = await getKeyFromIndexedDB(`${username}_mldsa_priv`, password);
    if (!ed25519Priv || !mldsaPriv) throw new Error('Could not load your private keys. Please log in again.');
    const privateKeyBundle = {
      preQuantum: {
        identitySigning: { privateKey: ed25519Priv },
      },
      postQuantum: {
        identitySigning: { privateKey: mldsaPriv },
      },
    };

    // 3. Sign the getbundle request
    const { headers, body } = createAuthenticatedRequest(
      'POST',
      '/api/keyhandler/getbundle',
      { username: recipientUsername },
      username,
      privateKeyBundle
    );
    const keyResponse = await fetch('/api/keyhandler/getbundle', {
      method: 'POST',
      headers,
      body
    });
    if (!keyResponse.ok) throw new Error('Failed to fetch recipient public key');
    const keyData = await keyResponse.json();
    const recipientPublicBundle = deserializeKeyBundlePublic(keyData.key_bundle);
    const recipientRawKem = extractX25519RawPublicKeyFromDER(recipientPublicBundle.preQuantum.identityKemPublicKey);

    // 4. Generate ephemeral key pair (libsodium)
    await sodium.ready;
    const ephKeyPair = sodium.crypto_kx_keypair();

    // 5. Derive shared secret
    const sharedSecret = sodium.crypto_scalarmult(ephKeyPair.privateKey, recipientRawKem);

    // 6. Encrypt FEK and MEK with shared secret
    const fekNonce = randomBytes(16);
    const mekNonce = randomBytes(16);
    const encryptedFek = encryptWithSharedSecret(new Uint8Array(clientData.fek), sharedSecret, fekNonce);
    const encryptedMek = encryptWithSharedSecret(new Uint8Array(clientData.mek), sharedSecret, mekNonce);

    // 7. Prepare share body (all binary fields as base64)
    const shareBody = {
      file_id: Number(item.id),
      shared_with_username: recipientUsername,
      encrypted_fek: Buffer.from(encryptedFek).toString('base64'),
      encrypted_fek_nonce: Buffer.from(fekNonce).toString('base64'),
      encrypted_mek: Buffer.from(encryptedMek).toString('base64'),
      encrypted_mek_nonce: Buffer.from(mekNonce).toString('base64'),
      ephemeral_public_key: Buffer.from(ephKeyPair.publicKey).toString('base64'),
      file_content_nonce: Buffer.from(clientData.fileNonce).toString('base64'),
      metadata_nonce: Buffer.from(clientData.metadataNonce).toString('base64')
    };

    // 8. Call share API using documented API, but authenticated
    const { headers: shareHeaders, body: shareBodyString } = createAuthenticatedRequest(
      'POST',
      '/api/fs/share',
      shareBody,
      username,
      privateKeyBundle
    );
    const shareRes = await fetch('/api/fs/share', {
      method: 'POST',
      headers: shareHeaders,
      body: shareBodyString
    });
    if (!shareRes.ok) {
      const errText = await shareRes.text();
      throw new Error('Failed to share file: ' + errText);
    }
    alert(`File shared with ${recipientUsername}!`);
  } catch (err) {
    alert('Share failed: ' + (err instanceof Error ? err.message : String(err)));
  }
}

const handleSharePrompt = (item: DriveItem) => {
  const recipient = window.prompt('Enter the username to share with:');
  if (recipient && recipient.trim()) {
    handleShare(item, recipient.trim());
  }
};

export default function DriveList({
  items,
  onFolderClick,
  getFileIcon,
  onDelete,
  onRename,
  onFileOpen,
  page,
  setPage,
  hasNextPage,
  onShare,
}: Props)
 {
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (error) {
      alert(error);
    }
  }, [error]);

  const handleDelete = async (item: DriveItem) => {
    if (!window.confirm(`Delete "${item.name}"?`)) return;
    try {
      // Authenticated request to /api/fs/delete
      const username = localStorage.getItem('drive_username') || '';
      let password = localStorage.getItem('drive_password') || '';
      if (!password) {
        password = window.prompt('Enter your password to unlock your keys:') || '';
        if (!password) throw new Error('Password required to unlock keys');
      }
      // Load private keys for signing
      const ed25519Priv = await getKeyFromIndexedDB(`${username}_ed25519_priv`, password);
      const mldsaPriv = await getKeyFromIndexedDB(`${username}_mldsa_priv`, password);
      if (!ed25519Priv || !mldsaPriv) throw new Error('Could not load your private keys. Please log in again.');
      const privateKeyBundle = {
        preQuantum: {
          identitySigning: { privateKey: ed25519Priv },
        },
        postQuantum: {
          identitySigning: { privateKey: mldsaPriv },
        },
      };
      const body = { file_id: Number(item.id) };
      const { headers, body: bodyString } = createAuthenticatedRequest(
        'POST',
        '/api/fs/delete',
        body,
        username,
        privateKeyBundle
      );
      const res = await fetch('/api/fs/delete', {
        method: 'POST',
        headers,
        body: bodyString
      });
      if (!res.ok) {
        const errText = await res.text();
        setError('Failed to delete file: ' + errText);
        return;
      }
      // Call parent onDelete to refresh list
      onDelete(item);
    } catch (err) {
      setError('Failed to delete file: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleRename = (item: DriveItem) => {
    onRename(item);
  };

  const handleDownload = async (item: FileItem) => {
    await onFileOpen(item);
  };

  const handleRevokeAccess = async (item: DriveItem) => {
    const usernameToRevoke = window.prompt('Enter the username to revoke access for:');
    if (!usernameToRevoke || !usernameToRevoke.trim()) return;
    try {
      const username = localStorage.getItem('drive_username') || '';
      let password = localStorage.getItem('drive_password') || '';
      if (!password) {
        password = window.prompt('Enter your password to unlock your keys:') || '';
        if (!password) throw new Error('Password required to unlock keys');
      }
      // Load private keys for signing
      const ed25519Priv = await getKeyFromIndexedDB(`${username}_ed25519_priv`, password);
      const mldsaPriv = await getKeyFromIndexedDB(`${username}_mldsa_priv`, password);
      if (!ed25519Priv || !mldsaPriv) throw new Error('Could not load your private keys. Please log in again.');
      const privateKeyBundle = {
        preQuantum: {
          identitySigning: { privateKey: ed25519Priv },
        },
        postQuantum: {
          identitySigning: { privateKey: mldsaPriv },
        },
      };
      const body = { file_id: Number(item.id), username: usernameToRevoke.trim() };
      const { headers, body: bodyString } = createAuthenticatedRequest(
        'POST',
        '/api/fs/revoke',
        body,
        username,
        privateKeyBundle
      );
      const res = await fetch('/api/fs/revoke', {
        method: 'POST',
        headers,
        body: bodyString
      });
      if (!res.ok) {
        const errText = await res.text();
        setError('Failed to revoke access: ' + errText);
        return;
      }
      alert('Access revoked for user: ' + usernameToRevoke.trim());
      // Optionally refresh file list here if needed
    } catch (err) {
      setError('Failed to revoke access: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

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
          <div className="p-8 text-center text-gray-500">This folder is empty</div>
        ) : (
          items.map((item) => (
            <div
              key={item.id}
              className="hover:bg-gray-750 group grid grid-cols-12 gap-4 p-4 transition-colors"
            >
              {/* Name */}
              <div className="col-span-6 flex items-center space-x-3">
                {getFileIcon(item.fileType)}
                <button
                  onClick={() => onFileOpen(item)}
                  className="w-full cursor-pointer truncate border-none bg-transparent text-left text-inherit transition-colors outline-none hover:text-blue-400"
                  style={{
                    background: "none",
                    border: "none",
                    padding: 0,
                    margin: 0,
                  }}
                >
                  {item.name}
                </button>
              </div>

              {/* Size */}
              <div className="col-span-2 flex items-center text-sm text-gray-400">
                {item.size}
              </div>

              {/* Modified */}
              <div className="col-span-3 flex items-center text-sm text-gray-400">
                {item.modified}
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
                    <DropdownMenuItem
                      className="text-white"
                      onClick={() => handleDownload(item)}
                    >
                      <Download className="mr-2 h-4 w-4" />
                      Download
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="text-white"
                      onClick={() => handleSharePrompt(item)}
                    >
                      <Share className="mr-2 h-4 w-4" />
                      Share
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="text-white"
                      onClick={() => handleRename(item)}
                    >
                      <FolderPen className="mr-2 h-4 w-4" />
                      Rename
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="text-red-400"
                      onClick={() => handleRevokeAccess(item)}
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Revoke Access
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="text-red-400"
                      onClick={() => handleDelete(item)}
                    >
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

      {/* Pagination */}
      <div className="flex justify-between p-4">
        <button
          disabled={page === 1 || isLoading}
          onClick={() => setPage(page - 1)}
          className="text-blue-400 disabled:text-gray-500"
        >
          Previous
        </button>
        <button
          disabled={!hasNextPage || isLoading}
          onClick={() => setPage(page + 1)}
          className="text-blue-400 disabled:text-gray-500"
        >
          Next
        </button>
      </div>
    </div>
  );
}
