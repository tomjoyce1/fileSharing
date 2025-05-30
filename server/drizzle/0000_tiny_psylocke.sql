CREATE TABLE `files_table` (
	`file_id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner_user_id` integer NOT NULL,
	`storage_path` text NOT NULL,
	`metadata` blob NOT NULL,
	`pre_quantum_signature` blob NOT NULL,
	`post_quantum_signature` blob NOT NULL,
	`upload_timestamp` integer DEFAULT (strftime('%s', 'now')) NOT NULL,
	FOREIGN KEY (`owner_user_id`) REFERENCES `users_table`(`user_id`) ON UPDATE cascade ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `files_table_storage_path_unique` ON `files_table` (`storage_path`);--> statement-breakpoint
CREATE INDEX `fk_Files_Owner_Users_idx` ON `files_table` (`owner_user_id`);--> statement-breakpoint
CREATE TABLE `shared_access_table` (
	`access_id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner_user_id` integer NOT NULL,
	`shared_with_user_id` integer,
	`file_id` integer NOT NULL,
	`encrypted_fek` blob NOT NULL,
	`encrypted_fek_salt` blob NOT NULL,
	`encrypted_fek_nonce` blob NOT NULL,
	`encrypted_mek` blob NOT NULL,
	`encrypted_mek_salt` blob NOT NULL,
	`encrypted_mek_nonce` blob NOT NULL,
	`shared_at` integer DEFAULT (strftime('%s', 'now')) NOT NULL,
	FOREIGN KEY (`owner_user_id`) REFERENCES `users_table`(`user_id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`shared_with_user_id`) REFERENCES `users_table`(`user_id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`file_id`) REFERENCES `files_table`(`file_id`) ON UPDATE cascade ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_user_file_access_idx` ON `shared_access_table` (`owner_user_id`,`shared_with_user_id`,`file_id`);--> statement-breakpoint
CREATE INDEX `fk_UFA_Files_idx` ON `shared_access_table` (`file_id`);--> statement-breakpoint
CREATE INDEX `fk_UFA_Sharer_idx` ON `shared_access_table` (`owner_user_id`);--> statement-breakpoint
CREATE INDEX `fk_UFA_Sharee_idx` ON `shared_access_table` (`shared_with_user_id`);--> statement-breakpoint
CREATE TABLE `users_table` (
	`user_id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`username` text NOT NULL,
	`public_key_bundle` blob NOT NULL,
	`created_at` integer DEFAULT (strftime('%s', 'now')) NOT NULL,
	`updated_at` integer DEFAULT (strftime('%s', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_table_username_unique` ON `users_table` (`username`);