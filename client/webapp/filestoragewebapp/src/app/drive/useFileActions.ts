import { gcm } from '@noble/ciphers/aes';
import { getKeyFromIndexedDB } from '@/lib/crypto/KeyUtils';
import { ctr } from '@noble/ciphers/aes';
import { getObjectFromIndexedDB } from '@/lib/crypto/KeyUtils';
import type { FileItem } from "./driveTypes";
import { deserializeKeyBundlePublic } from '@/lib/crypto/KeyHelper';
import sodium from 'libsodium-wrappers';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { createAuthenticatedRequest } from './utils/encryption';
import { extractEd25519RawPublicKeyFromDER } from '@/lib/crypto/KeyHelper';
import { createFileSignatureCanonical } from './utils/encryption';
import { getDecryptedPrivateKey } from '@/components/AuthPage';
import { decryptWithSharedSecret } from '@/app/drive/utils/encryption';
import { saveObjectToIndexedDB } from '@/lib/crypto/KeyUtils';

// Placeholder types for missing definitions
type DriveItem = { id: string; type: string };
type FileMetadataListItem = { id: string; metadata: string };
type FileMetadata = { id: string; decryptedMetadata: string };

export function useFileActions(fetchFiles: (page: number) => Promise<void>, page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const ensureFileItem = (item: any): FileItem => {
    console.log('Ensuring file item format', { item });
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
    console.log('Initiating file delete', { fileId: fileItem.id, fileName: fileItem.name });
    void (async () => {
      try {
        const response = await fetch(`/api/fs/delete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_id: Number(fileItem.id) })
        });
        if (!response.ok) {
          console.log('Delete request failed', { 
            fileId: fileItem.id, 
            status: response.status 
          });
          throw new Error('Failed to delete file');
        }
        console.log('File deleted successfully', { fileId: fileItem.id });
        // Refresh file list after successful delete
        void fetchFiles(page);
      } catch (err) {
        console.log('Delete operation failed', { 
          fileId: fileItem.id,
          error: err instanceof Error ? err.message : String(err)
        });
        setError('Failed to delete file');
      }
    })();
  };

  

  const decryptMetadata = async (file: any) => {
    const fileId = file.file_id ?? file.id;
    console.log('Starting metadata decryption', { fileId });
    
    const clientDataStr = localStorage.getItem(`client_data_${fileId}`);
    if (!clientDataStr) {
      console.log('Missing client data for metadata decryption', { fileId });
      throw new Error('Missing decryption keys for this file.');
    }
    
    const clientData = JSON.parse(clientDataStr);
    let password = (window as any).inMemoryPassword;
    if (!password) {
      console.log('Requesting password for key decryption');
      password = window.prompt('Enter your password to unlock your keys:') || undefined;
      if (!password) {
        console.log('No password provided for key decryption');
        throw new Error('Password required to unlock keys');
      }
      (window as any).inMemoryPassword = password;
    }
    
    try {
      const mek = new Uint8Array(clientData.mek);
      const metadataNonce = new Uint8Array(clientData.metadataNonce);
      const encryptedMetadata = typeof file.metadata === 'string' 
        ? Uint8Array.from(atob(file.metadata), c => c.charCodeAt(0)) 
        : file.metadata;
      
      console.log('Decrypting metadata');
      const decrypted = gcm(mek, metadataNonce).decrypt(encryptedMetadata);
      const result = JSON.parse(new TextDecoder().decode(decrypted));
      
      console.log('Metadata decryption successful', { fileId });
      return result;
    } catch (err) {
      console.log('Metadata decryption failed', { 
        fileId,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  };

  const handleFileOpen = async (file: any) => {
    try {
      console.log('Starting file download process', { 
        fileId: file.id, 
        fileName: file.name 
      });
      
      // 1. Load client_data from IndexedDB (or fallback to localStorage)
      let clientData = null;
      const fileId = file.file_id ?? file.id;
      try {
        clientData = await getObjectFromIndexedDB(fileId.toString());
        console.log('Retrieved client data from IndexedDB', { fileId });
      } catch (e) {
        console.log('Failed to read from IndexedDB, falling back to localStorage', { 
          fileId,
          error: e instanceof Error ? e.message : String(e)
        });
      }
      
      if (!clientData) {
        const clientDataStr = localStorage.getItem(`client_data_${fileId}`);
        if (clientDataStr) {
          clientData = JSON.parse(clientDataStr);
          console.log('Retrieved client data from localStorage', { fileId });
        }
      }
      
      if (!clientData) {
        console.log('Missing client data for file download', { fileId });
        throw new Error('Missing decryption keys for this file.');
      }

      // 2. Make authenticated request to /api/fs/download
      const username = localStorage.getItem('drive_username') || '';
      console.log('Preparing authenticated download request', { fileId, username });
      
      let password = (window as any).inMemoryPassword;
      if (!password) {
        console.log('Requesting password for key decryption');
        password = window.prompt('Enter your password to unlock your keys:') || undefined;
        if (!password) {
          console.log('No password provided for key decryption');
          throw new Error('Password required to unlock keys');
        }
        (window as any).inMemoryPassword = password;
      }

      // Load private keys for signing
      const ed25519Priv = await getDecryptedPrivateKey(username, 'ed25519');
      const mldsaPriv = await getDecryptedPrivateKey(username, 'mldsa');
      if (!ed25519Priv || !mldsaPriv) {
        console.log('Failed to load private keys for download', { username });
        throw new Error('Could not load your private keys. Please log in again.');
      }
      
      console.log('Successfully loaded private keys');
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

      console.log('Sending download request to server');
      const res = await fetch(`/api/fs/download`, {
        method: 'POST',
        headers,
        body: bodyString
      });

      if (!res.ok) {
        const errText = await res.text();
        console.log('Download request failed', { 
          fileId,
          status: res.status,
          error: errText 
        });
        throw new Error('Failed to download file: ' + errText);
      }

      const data = await res.json();
      console.log('Received file data from server');

      // If we don't have client data and this is a shared file, derive it from shared_access
      if (!clientData && data.shared_access) {
        console.log('Deriving client data from shared access', { fileId });
        try {
          // Get the ephemeral public key from shared access
          const ephemeralPublicKeyBytes = Buffer.from(data.shared_access.ephemeral_public_key, 'base64');
          
          // Load X25519 KEM private key
          const x25519Priv = await getDecryptedPrivateKey(username, 'x25519');
          if (!x25519Priv) {
            throw new Error('Could not load X25519 KEM private key');
          }
          
          // Derive shared secret using our X25519 private key and the ephemeral public key
          await sodium.ready;
          const sharedSecret = sodium.crypto_scalarmult(
            x25519Priv, // Our X25519 KEM private key
            ephemeralPublicKeyBytes
          );

          // Decrypt FEK and MEK using the shared secret
          const fekNonce = Buffer.from(data.shared_access.encrypted_fek_nonce, 'base64');
          const fek = decryptWithSharedSecret(
            Buffer.from(data.shared_access.encrypted_fek, 'base64'),
            sharedSecret,
            fekNonce
          );

          const mekNonce = Buffer.from(data.shared_access.encrypted_mek_nonce, 'base64');
          const mek = decryptWithSharedSecret(
            Buffer.from(data.shared_access.encrypted_mek, 'base64'),
            sharedSecret,
            mekNonce
          );

          // Create client data from decrypted keys and nonces
          clientData = {
            fek: Array.from(fek),
            mek: Array.from(mek),
            fileNonce: Array.from(Buffer.from(data.shared_access.file_content_nonce, 'base64')),
            metadataNonce: Array.from(Buffer.from(data.shared_access.metadata_nonce, 'base64'))
          };

          // Store the derived client data for future use
          try {
            await saveObjectToIndexedDB(fileId.toString(), clientData);
            console.log('Stored derived client data in IndexedDB', { fileId });
          } catch (e) {
            console.log('Failed to store derived client data in IndexedDB', { 
              fileId,
              error: e instanceof Error ? e.message : String(e)
            });
            // Fallback to localStorage
            localStorage.setItem(`client_data_${fileId}`, JSON.stringify(clientData));
            console.log('Stored derived client data in localStorage', { fileId });
          }
        } catch (e) {
          console.log('Failed to derive client data from shared access', { 
            fileId,
            error: e instanceof Error ? e.message : String(e)
          });
          throw new Error('Failed to derive decryption keys from shared access');
        }
      }

      if (!clientData) {
        console.log('Missing client data for file download', { fileId });
        throw new Error('Missing decryption keys for this file.');
      }

      // Load public key bundle for signature verification
      let pubkeyBundle = null;
      try {
        // Get the owner's username from the server response
        const ownerUsername = data.owner_username;
        if (!ownerUsername) {
          console.log('No owner username in response data', { data });
          throw new Error('Missing owner information in server response');
        }
        console.log('Loading public key bundle for owner', { ownerUsername });
        
        // First try to get from IndexedDB
        const pubkeyBundleStr = await getObjectFromIndexedDB(`${ownerUsername}_pubkey_bundle`);
        if (!pubkeyBundleStr) {
          // If not in IndexedDB, try to fetch from server
          console.log('Public key bundle not found in IndexedDB, fetching from server');
          const { headers, body: bodyString } = createAuthenticatedRequest(
            'POST',
            '/api/keyhandler/getbundle',
            { username: ownerUsername },
            username,
            privateKeyBundle
          );
          const response = await fetch(`/api/keyhandler/getbundle`, {
            method: 'POST',
            headers,
            body: bodyString
          });
          if (!response.ok) {
            throw new Error('Failed to fetch owner\'s public key bundle');
          }
          const serverBundle = await response.json();
          
          // Store in IndexedDB for future use
          await saveObjectToIndexedDB(`${ownerUsername}_pubkey_bundle`, serverBundle.key_bundle);
          pubkeyBundle = deserializeKeyBundlePublic(serverBundle.key_bundle);
        } else {
          const parsedBundle = typeof pubkeyBundleStr === 'string'
            ? JSON.parse(pubkeyBundleStr)
            : pubkeyBundleStr;
          pubkeyBundle = deserializeKeyBundlePublic(parsedBundle);
        }
        
        console.log('Successfully loaded public key bundle for owner', { ownerUsername });
      } catch (e) {
        console.log('Failed to load/deserialize public key bundle', { 
          error: e instanceof Error ? e.message : String(e)
        });
        setError('Could not load owner\'s public key bundle for signature verification.');
        return;
      }

      // Verify signatures
      try {
        console.log('Starting signature verification');
        await sodium.ready;
        const ownerUsername = data.owner_username;
        if (!ownerUsername) {
          throw new Error('Missing owner information in server response');
        }
        
        let metadataBase64;
        if (typeof data.metadata === 'string') {
          metadataBase64 = data.metadata;
        } else if (data.metadata && data.metadata.type === 'Buffer' && Array.isArray(data.metadata.data)) {
          metadataBase64 = btoa(String.fromCharCode(...data.metadata.data));
        } else {
          console.log('Invalid metadata format');
          throw new Error('Invalid metadata format');
        }

        const canonicalString = await createFileSignatureCanonical(ownerUsername, data.file_content, metadataBase64);
        const canonicalBytes = new TextEncoder().encode(canonicalString);
        const preQuantumSig = Uint8Array.from(atob(data.pre_quantum_signature), c => c.charCodeAt(0));
        
        const ed25519Der = pubkeyBundle.preQuantum.identitySigningPublicKey;
        const ed25519Raw = extractEd25519RawPublicKeyFromDER(
          ed25519Der instanceof Uint8Array ? ed25519Der : new Uint8Array(ed25519Der)
        );

        const postQuantumSig = Uint8Array.from(atob(data.post_quantum_signature), c => c.charCodeAt(0));
        const mldsaPub = pubkeyBundle.postQuantum.identitySigningPublicKey;

        const preQuantumValid = sodium.crypto_sign_verify_detached(preQuantumSig, canonicalBytes, ed25519Raw);
        const postQuantumValid = ml_dsa87.verify(mldsaPub, canonicalBytes, postQuantumSig);

        console.log('Signature verification results', { 
          preQuantumValid, 
          postQuantumValid 
        });

        if (!preQuantumValid || !postQuantumValid) {
          console.log('Signature verification failed');
          setError('Signature verification failed. File may be tampered.');
          return;
        }
      } catch (e) {
        console.log('Signature verification error', { 
          error: e instanceof Error ? e.message : String(e)
        });
        setError('Signature verification error: ' + (e as Error).message);
        return;
      }

      // Decrypt file content
      try {
        console.log('Starting file content decryption');
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
        
        console.log('File downloaded and decrypted successfully', { 
          fileId,
          fileName: file.name 
        });
      } catch (e) {
        console.log('File decryption error', { 
          fileId,
          error: e instanceof Error ? e.message : String(e)
        });
        setError('Decryption error: ' + (e as Error).message);
      }
    } catch (err) {
      console.log('File download process failed', { 
        fileId: file.id,
        error: err instanceof Error ? err.message : String(err)
      });
      setError((err as Error).message);
    }
  };

  return { handleDelete, ensureFileItem, decryptMetadata, handleFileOpen };
}

export async function fetchFileMetadata(fileId: string) {
  console.log(`[useFileActions] Fetching metadata for fileId=${fileId}`);
  //what goes here?
}