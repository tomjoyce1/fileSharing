// Basic types for the application
export interface FileMetadata {
  original_filename: string;
  file_size_bytes: number;
  file_type: string;
}

export interface FileMetadataListItem {
  id: string;
  metadata: string | Uint8Array;
  owner_user_id: string;
  created_at: string;
  updated_at: string;
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
