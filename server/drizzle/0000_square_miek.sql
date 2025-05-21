CREATE TABLE `Files` (
	`file_id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner_user_id` integer NOT NULL,
	`storage_path` text NOT NULL,
	`encrypted_original_filename` blob NOT NULL,
	`filename_encryption_iv` text NOT NULL,
	`file_content_auth_tag` blob NOT NULL,
	`file_size_bytes` integer NOT NULL,
	`upload_timestamp` integer DEFAULT (strftime('%s', 'now')) NOT NULL,
	FOREIGN KEY (`owner_user_id`) REFERENCES `Users`(`user_id`) ON UPDATE cascade ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `Files_storage_path_unique` ON `Files` (`storage_path`);--> statement-breakpoint
CREATE INDEX `fk_Files_Owner_Users_idx` ON `Files` (`owner_user_id`);--> statement-breakpoint
CREATE TABLE `User_File_Access` (
	`access_id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`file_id` integer NOT NULL,
	`kyber_encapsulated_key` blob NOT NULL,
	`encrypted_dek_with_shared_secret` blob NOT NULL,
	`dek_encryption_iv` text NOT NULL,
	`shared_by_user_id` integer,
	`access_granted_at` integer DEFAULT (strftime('%s', 'now')) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `Users`(`user_id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`file_id`) REFERENCES `Files`(`file_id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`shared_by_user_id`) REFERENCES `Users`(`user_id`) ON UPDATE cascade ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_user_file_access_idx` ON `User_File_Access` (`user_id`,`file_id`);--> statement-breakpoint
CREATE INDEX `fk_UFA_Users_idx` ON `User_File_Access` (`user_id`);--> statement-breakpoint
CREATE INDEX `fk_UFA_Files_idx` ON `User_File_Access` (`file_id`);--> statement-breakpoint
CREATE INDEX `fk_UFA_SharedBy_idx` ON `User_File_Access` (`shared_by_user_id`);--> statement-breakpoint
CREATE TABLE `Users` (
	`user_id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`username` text NOT NULL,
	`password_hash` text NOT NULL,
	`password_salt` text NOT NULL,
	`user_public_key` blob NOT NULL,
	`client_sk_protection_salt` text NOT NULL,
	`created_at` integer DEFAULT (strftime('%s', 'now')) NOT NULL,
	`updated_at` integer DEFAULT (strftime('%s', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `Users_username_unique` ON `Users` (`username`);--> statement-breakpoint
CREATE UNIQUE INDEX `Users_client_sk_protection_salt_unique` ON `Users` (`client_sk_protection_salt`);