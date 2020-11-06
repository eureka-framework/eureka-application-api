CREATE TABLE `user` (
    `user_id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'User Id',
    `user_email` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'User email address',
    `user_password` varbinary(100) NOT NULL COMMENT 'Bcrypted hashed user password',
    `user_first_name` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'User first name',
    `user_last_name` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'User last name',
    `user_pseudo` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'User last name',
    `user_token_hash_list` varbinary(1000) NOT NULL DEFAULT '[]' COMMENT 'Json list of last 10 active JWT hash',
    `user_is_enabled` tinyint(1) NOT NULL DEFAULT 1 COMMENT '0: disabled, 1: enabled',
    `user_date_first_access` datetime DEFAULT NULL COMMENT 'Date of the first access to the application (with valid token)',
    `user_date_last_access` datetime DEFAULT NULL COMMENT 'Date of the last access the application (with valid token)',
    `user_date_create` datetime NOT NULL DEFAULT current_timestamp(),
    `user_date_update` datetime DEFAULT NULL,
    PRIMARY KEY (`user_id`),
    UNIQUE KEY `unq_user_email` (`user_email`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Table to store credential & basic information about application users';
