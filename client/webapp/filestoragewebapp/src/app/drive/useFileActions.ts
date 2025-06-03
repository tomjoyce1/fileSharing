import { gcm } from '@noble/ciphers/aes';
import { getKeyFromIndexedDB } from '@/lib/crypto/KeyUtils';
import { ctr } from '@noble/ciphers/aes';
import { getObjectFromIndexedDB } from '@/lib/crypto/KeyUtils';
import type { FileItem } from "./driveTypes";
import { deserializeKeyBundlePublic } from '@/lib/crypto/KeyHelper';
import sodium from 'libsodium-wrappers';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { createAuthenticatedRequest } from './utils/encryption';

// Placeholder types for missing definitions
type DriveItem = { id: string; type: string };
type FileMetadataListItem = { id: string; metadata: string };
type FileMetadata = { id: string; decryptedMetadata: string };

export function useFileActions(fetchFiles: (page: number) => Promise<void>, page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const ensureFileItem = (item: any): FileItem => {
    return {
      id: item.id,
      name: item.name || "Unknown",
      type: "file",
      fileType: item.fileType || "document",
      size: item.size || "-",
      modified: item.modified || "-",
      url: item.url || '',
      encrypted: item.encrypted || false,
    };
  };

  const handleDelete = (item: any) => {
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

  const handleRename = (item: any): FileItem => {
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

  const decryptMetadata = async (file: any) => {
    const fileId = file.file_id ?? file.id;
    const clientDataStr = localStorage.getItem(`client_data_${fileId}`);
    if (!clientDataStr) throw new Error('Missing decryption keys for this file.');
    const clientData = JSON.parse(clientDataStr);
    const username = localStorage.getItem('drive_username') || '';
    let password = localStorage.getItem('drive_password') || '';
    if (!password) {
      password = window.prompt('Enter your password to unlock your keys:') || '';
      if (!password) throw new Error('Password required to unlock keys');
    }
    const mek = new Uint8Array(clientData.mek);
    const metadataNonce = new Uint8Array(clientData.metadataNonce);
    const encryptedMetadata = typeof file.metadata === 'string' ? Uint8Array.from(atob(file.metadata), c => c.charCodeAt(0)) : file.metadata;
    const decrypted = gcm(mek, metadataNonce).decrypt(encryptedMetadata);
    return JSON.parse(new TextDecoder().decode(decrypted));
  };

  const handleFileOpen = async (file: any) => {
    try {
      console.log('[FileActions][Download] Starting download for file:', file);
      // 1. Load client_data from IndexedDB (or fallback to localStorage)
      let clientData = null;
      const fileId = file.file_id ?? file.id;
      try {
        clientData = await getObjectFromIndexedDB(fileId.toString());
        console.log(`[FileActions][Download] getObjectFromIndexedDB(${fileId}):`, clientData);
      } catch (e) {
        console.warn(`[FileActions][Download] Error reading from IndexedDB for file_id=${fileId}:`, e);
      }
      if (!clientData) {
        const clientDataStr = localStorage.getItem(`client_data_${fileId}`);
        if (clientDataStr) {
          clientData = JSON.parse(clientDataStr);
          console.log(`[FileActions][Download] Fallback to localStorage for file_id=${fileId}:`, clientData);
        }
      }
      if (!clientData) throw new Error('Missing decryption keys for this file.');
      // 2. Make authenticated request to /api/fs/download (with signatures and timestamp)
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
      const body = { file_id: Number(fileId) };
      const { headers, body: bodyString } = createAuthenticatedRequest(
        'POST',
        '/api/fs/download',
        body,
        username,
        privateKeyBundle
      );
      console.log('[FileActions][Download] Making signed POST /api/fs/download for file_id:', fileId, headers, bodyString);
      const res = await fetch(`/api/fs/download`, {
        method: 'POST',
        headers,
        body: bodyString
      });
      if (!res.ok) {
        const errText = await res.text();
        console.error('[FileActions][Download] Download failed:', errText);
        throw new Error('Failed to download file: ' + errText);
      }
      const data = await res.json();
      console.log('[FileActions][Download] Downloaded data:', data);

      // Load public key bundle
      let pubkeyBundle = null;
      try {
        const pubkeyBundleStr = await getObjectFromIndexedDB(`${username}_pubkey_bundle`);
        if (!pubkeyBundleStr) throw new Error('No public key bundle found');
        pubkeyBundle = deserializeKeyBundlePublic(pubkeyBundleStr);
        console.log('[FileActions][Download] Loaded public key bundle:', pubkeyBundle);
      } catch (e) {
        console.error('[FileActions][Download] Failed to load/deserialize public key bundle:', e);
        setError('Could not load your public key bundle for signature verification.');
        return;
      }

      // Verify signatures
      try {
        await sodium.ready;
        const canonicalString = data.canonical_string || '';
        const canonicalBytes = new TextEncoder().encode(canonicalString);
        const preQuantumSig = Uint8Array.from(atob(data.pre_quantum_signature), c => c.charCodeAt(0));
        const ed25519Pub = pubkeyBundle.preQuantum.identitySigningPublicKey;
        const preQuantumValid = sodium.crypto_sign_verify_detached(preQuantumSig, canonicalBytes, ed25519Pub);
        console.log('[FileActions][Download] Pre-quantum signature valid:', preQuantumValid);

        const postQuantumSig = Uint8Array.from(atob(data.post_quantum_signature), c => c.charCodeAt(0));
        const mldsaPub = pubkeyBundle.postQuantum.identitySigningPublicKey;
        const postQuantumValid = ml_dsa87.verify(mldsaPub, canonicalBytes, postQuantumSig);
        console.log('[FileActions][Download] Post-quantum signature valid:', postQuantumValid);

        if (!preQuantumValid || !postQuantumValid) {
          setError('Signature verification failed. File may be tampered.');
          console.error('[FileActions][Download] Signature verification failed.');
          return;
        }
      } catch (e) {
        setError('Signature verification error: ' + (e as Error).message);
        console.error('[FileActions][Download] Signature verification error:', e);
        return;
      }

      // Decrypt file content
      try {
        const encryptedFileContent = Uint8Array.from(atob(data.file_content), c => c.charCodeAt(0));
        const fileNonce = new Uint8Array(clientData.fileNonce || clientData.file_nonce);
        const fek = new Uint8Array(clientData.fek);
        const fileCipher = ctr(fek, fileNonce);
        const decryptedContent = fileCipher.decrypt(encryptedFileContent);

        // Trigger download
        const blob = new Blob([decryptedContent]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name || 'downloaded_file';
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        console.log('[FileActions][Download] File downloaded and decrypted successfully.');
      } catch (e) {
        setError('Decryption error: ' + (e as Error).message);
        console.error('[FileActions][Download] Decryption error:', e);
      }
    } catch (err) {
      setError((err as Error).message);
      console.error('[FileActions][Download] Error:', err);
    }
  };

  return { handleDelete, handleRename, ensureFileItem, decryptMetadata, handleFileOpen };
}




export async function fetchFileMetadata(fileId: string) {
  console.log(`[useFileActions] Fetching metadata for fileId=${fileId}`);
  //what goes here?
}
