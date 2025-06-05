// Basic types for the application
export interface FileMetadata {
  original_filename: string;
  file_size_bytes: number;
  file_type: string;
}

export interface FileMetadataListItem {
  file_id: number;
  metadata: string; // base64 encoded encrypted metadata for transport
  pre_quantum_signature: string;
  post_quantum_signature: string;
  is_owner: boolean;
  upload_timestamp?: number;
  shared_access?: {
    encrypted_fek: string;
    encrypted_fek_nonce: string;
    encrypted_mek: string;
    encrypted_mek_nonce: string;
    ephemeral_public_key: string;
    file_content_nonce: string;
    metadata_nonce: string;
  };
}

// Response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface ListFilesResponse {
  files: FileMetadataListItem[];
  total_count: number;
  page_size: number;
  current_page: number;
}
