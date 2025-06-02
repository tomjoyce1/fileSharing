export interface FileItem {
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

export type DriveItem = FileItem;

export interface FileMetadataListItem {
  id: string;
  file_id?: number;
  metadata: string | Uint8Array;
  upload_timestamp?: number;
}

export interface FileMetadata {
  original_filename: string;
  file_size_bytes: number;
  file_type: string;
}
