-- アタックデータ・ベースの作成
create database attackblock;

-- 接続ユーザの作成
grant all privileges on attackblock.* to user@localhost identified by 'password';

use attackblock;

-- テーブルの作成
CREATE TABLE `acltable` (
  `id` int(12) NOT NULL,
  `blockip` varchar(32) NOT NULL,
  `blockaclno`     int(6) NOT NULL,
  `created` datetime NOT NULL
) ENGINE=InnoDB character set utf8;

ALTER TABLE `acltable` ADD PRIMARY KEY (`id`);
ALTER TABLE `acltable` MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;