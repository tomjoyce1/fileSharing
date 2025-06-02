import { storeEncryptionKeys, getPrivateKeyFromIndexedDB } from "@/lib/crypto/KeyUtils";
import { generateFEKComponents, deriveFEK, encryptFileBuffer, encryptMetadataWithFEK } from "@/lib/crypto/encryptor";
import sodium from "libsodium-wrappers";

export function useFileUpload(fetchFiles: (page: number) => Promise<void>, page: number, setError: (msg: string|null) => void, setIsLoading: (b: boolean) => void) {
  const handleFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setIsLoading(true);
    setError(null);
    try {
      await sodium.ready;
      const uuid = crypto.randomUUID();
      const { s_pre, s_post } = await generateFEKComponents();
      const fek = await deriveFEK(s_pre, s_post);
      const fileBuffer = await file.arrayBuffer();
      const { encryptedData, nonce: fileNonce } = await encryptFileBuffer(fek, fileBuffer);
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
      const { encryptedData: encryptedMetadata, nonce: metadataNonce } =
        await encryptMetadataWithFEK(fek, metadata);
      await storeEncryptionKeys(uuid, {
        s_pre: Array.from(s_pre),
        s_post: Array.from(s_post),
        file_nonce: Array.from(fileNonce),
        metadata_nonce: Array.from(metadataNonce)
      });
      const username = localStorage.getItem("drive_username");
      if (!username) throw new Error("You are not logged in. Please log in again.");
      // Prepare upload body (no owner_user_id, add signatures)


const file_content_b64 = sodium.to_base64(encryptedData, sodium.base64_variants.ORIGINAL);
const metadata_b64 = sodium.to_base64(encryptedMetadata, sodium.base64_variants.ORIGINAL);
// Generate signatures for file record (for DB fields)
const KeyUtils = await import("@/lib/crypto/KeyUtils");
const { preQuantumSignature, postQuantumSignature } = await KeyUtils.signFileRecord(
  uuid, // use uuid as fileId
  username,
  encryptedData,
  encryptedMetadata
);
const pre_quantum_signature = sodium.to_base64(preQuantumSignature, sodium.base64_variants.ORIGINAL);
const post_quantum_signature = postQuantumSignature
  ? sodium.to_base64(postQuantumSignature, sodium.base64_variants.ORIGINAL)
  : "";
const uploadBody = {
  file_content: file_content_b64,
  metadata: metadata_b64,
  pre_quantum_signature,
  post_quantum_signature
};

      // --- Step 2: Build canonical string for header signature ---
      const timestamp = new Date().toISOString();
      const canonicalString = `${username}|${timestamp}|POST|/api/fs/upload|${JSON.stringify(uploadBody)}`;
      const canonicalBytes = new TextEncoder().encode(canonicalString);

      // --- Step 3: Sign canonical string for header (do NOT reuse file record signatures) ---
      const edPrivateKey = await getPrivateKeyFromIndexedDB(`${username}_ed25519_priv`);
      if (!edPrivateKey) throw new Error("Missing Ed25519 key");
      await sodium.ready;
      const preSigBytes = sodium.crypto_sign_detached(canonicalBytes, edPrivateKey);
      const preSigB64 = sodium.to_base64(preSigBytes, sodium.base64_variants.ORIGINAL);
      let postSigB64 = "";
      try {
        const mldsaKey = await KeyUtils.getKeyFromIndexedDB(`${username}_mldsa_priv`);
        if (mldsaKey && mldsaKey.length === KeyUtils.ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH) {
          const mlSig = KeyUtils.signMLDSA(mldsaKey, canonicalBytes);
          postSigB64 = sodium.to_base64(mlSig, sodium.base64_variants.ORIGINAL);
        }
      } catch (e) {
        console.warn("[FileUpload] ML-DSA signature for header failed or missing:", e);
      }
      const signatureHeader = `${preSigB64}||${postSigB64}`;


    //   loggin

    console.log("[Upload Debug] username:", username);
console.log("[Upload Debug] timestamp:", timestamp);
console.log("[Upload Debug] canonicalString:", canonicalString);
console.log("[Upload Debug] uploadBody:", uploadBody);
console.log("[Upload Debug] Ed25519 signature (header, base64):", preSigB64);
console.log("[Upload Debug] ML-DSA signature (header, base64):", postSigB64);
console.log("[Upload Debug] X-Signature header:", signatureHeader);
console.log("[Upload Debug] Ed25519 key length:", edPrivateKey.length, "first bytes:", Array.from(edPrivateKey).slice(0, 8));
if (typeof mldsaKey !== 'undefined') {
  console.log("[Upload Debug] ML-DSA key length:", mldsaKey.length, "first bytes:", Array.from(mldsaKey).slice(0, 8));
}


      // --- Step 4: Send request ---
      const response = await fetch('/api/fs/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Username': username,
          'X-Timestamp': timestamp,
          'X-Signature': signatureHeader,
        },
        body: JSON.stringify(uploadBody),
      });
      if (!response.ok) {
        const errorText = await response.text();
        // Only log error, do not show popup
        console.error(`Upload failed: ${errorText}`);
        setError(`Upload failed: ${errorText}`);
        return;
      }
      await fetchFiles(page);
    } catch (err) {
      // Only log error, do not show popup
      console.error(err);
      setError(err instanceof Error ? err.message : 'Failed to upload file');
    } finally {
      setIsLoading(false);
      if (event.target) {
        event.target.value = '';
      }
    }
  };
  return { handleFileChange };
}
