// types and data calls to endpoints

export type FileItem = {
  id: string;
  name: string;
  type: "file";
  fileType: "image" | "document" | "audio" | "video" | "pdf";
  size: string;
  modified: string;
  url: string;
  encrypted?: boolean;
  nonce?: Uint8Array;
};

export type FolderItem = {
  id: string;
  name: string;
  type: "folder";
  children: (FileItem | FolderItem)[];
};

export type DriveItem = FileItem | FolderItem;

export const mockData = {
  root: {
    id: "root",
    name: "My Drive",
    type: "folder" as const,
    children: [
      {
        id: "documents",
        name: "Documents",
        type: "folder" as const,
        children: [
          {
            id: "resume",
            name: "Resume.pdf",
            type: "file" as const,
            fileType: "pdf" as const,
            size: "2.4 MB",
            modified: "2 days ago",
            url: "https://example.com/resume.pdf",
          },
          {
            id: "cover-letter",
            name: "Cover Letter.docx",
            type: "file" as const,
            fileType: "document" as const,
            size: "1.2 MB",
            modified: "1 week ago",
            url: "https://example.com/cover-letter.docx",
          },
        ],
      },
      {
        id: "photos",
        name: "Photos",
        type: "folder" as const,
        children: [
          {
            id: "vacation",
            name: "Vacation",
            type: "folder" as const,
            children: [
              {
                id: "beach1",
                name: "Beach_Photo_1.jpg",
                type: "file" as const,
                fileType: "image" as const,
                size: "5.2 MB",
                modified: "3 days ago",
                url: "https://example.com/beach1.jpg",
              },
              {
                id: "beach2",
                name: "Beach_Photo_2.jpg",
                type: "file" as const,
                fileType: "image" as const,
                size: "4.8 MB",
                modified: "3 days ago",
                url: "https://example.com/beach2.jpg",
              },
            ],
          },
          {
            id: "profile",
            name: "Profile_Picture.png",
            type: "file" as const,
            fileType: "image" as const,
            size: "1.8 MB",
            modified: "1 month ago",
            url: "https://example.com/profile.png",
          },
        ],
      },
      {
        id: "music",
        name: "Music",
        type: "folder" as const,
        children: [
          {
            id: "song1",
            name: "Favorite_Song.mp3",
            type: "file" as const,
            fileType: "audio" as const,
            size: "8.4 MB",
            modified: "2 weeks ago",
            url: "https://example.com/song1.mp3",
          },
        ],
      },
      {
        id: "presentation",
        name: "Project_Presentation.pptx",
        type: "file" as const,
        fileType: "document" as const,
        size: "15.6 MB",
        modified: "5 days ago",
        url: "https://example.com/presentation.pptx",
      },
      {
        id: "video",
        name: "Demo_Video.mp4",
        type: "file" as const,
        fileType: "video" as const,
        size: "125.3 MB",
        modified: "1 week ago",
        url: "https://example.com/demo.mp4",
      },
    ],
  },
};
