-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Feb 12, 2014 at 09:20 PM
-- Server version: 5.5.33-1
-- PHP Version: 5.5.8-3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `xmppmessenger`
--

-- --------------------------------------------------------

--
-- Table structure for table `presence`
--

CREATE TABLE `presence` (
  `userid` char(40) NOT NULL COMMENT 'User ID',
  `timestamp` datetime DEFAULT NULL COMMENT 'Cache entry timestamp',
  `status` varchar(500) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL COMMENT 'Status message',
  `show` varchar(30) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL COMMENT 'Availability',
  `priority` smallint(5) NOT NULL DEFAULT '0' COMMENT 'Priority',
  `fingerprint` char(40) DEFAULT NULL COMMENT 'Public key fingerprint',
  PRIMARY KEY (`userid`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii COMMENT='User presence cache';

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE `servers` (
  `fingerprint` char(40) NOT NULL COMMENT 'Server key fingerprint',
  `host` varchar(100) NOT NULL COMMENT 'Server address',
  PRIMARY KEY (`fingerprint`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii COMMENT='Servers';

-- --------------------------------------------------------

--
-- Table structure for table `stanzas_iq`
--

CREATE TABLE `stanzas_iq` (
  `id` varchar(30) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'Stanza ID',
  `sender` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'From',
  `recipient` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'To',
  `type` varchar(15) CHARACTER SET ascii DEFAULT NULL COMMENT 'Stanza type',
  `content` mediumblob NOT NULL COMMENT 'Stanza content',
  `timestamp` bigint(20) unsigned NOT NULL COMMENT 'Stanza timestamp',
  `expire_timestamp` datetime DEFAULT NULL COMMENT 'Stanza expiration timestamp',
  PRIMARY KEY (`id`),
  UNIQUE KEY `key` (`sender`,`recipient`,`type`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='Pending stanzas (iq)';

-- --------------------------------------------------------

--
-- Table structure for table `stanzas_message`
--

CREATE TABLE `stanzas_message` (
  `id` varchar(30) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'Stanza ID',
  `sender` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'From',
  `recipient` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'To',
  `type` varchar(15) CHARACTER SET ascii DEFAULT NULL COMMENT 'Stanza type',
  `content` mediumblob NOT NULL COMMENT 'Stanza content',
  `timestamp` bigint(20) unsigned NOT NULL COMMENT 'Stanza timestamp',
  `expire_timestamp` datetime DEFAULT NULL COMMENT 'Stanza expiration timestamp',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='Pending stanzas (message)';

-- --------------------------------------------------------

--
-- Table structure for table `stanzas_presence`
--

CREATE TABLE `stanzas_presence` (
  `id` varchar(30) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'Stanza ID',
  `sender` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'From',
  `recipient` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'To',
  `type` varchar(15) CHARACTER SET ascii DEFAULT NULL COMMENT 'Stanza type',
  `content` mediumblob NOT NULL COMMENT 'Stanza content',
  `timestamp` bigint(20) unsigned NOT NULL COMMENT 'Stanza timestamp',
  `expire_timestamp` datetime DEFAULT NULL COMMENT 'Stanza expiration timestamp',
  PRIMARY KEY (`id`),
  UNIQUE KEY `key` (`sender`,`recipient`,`type`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='Pending stanzas (presence)';

-- --------------------------------------------------------

--
-- Table structure for table `validations`
--

CREATE TABLE `validations` (
  `userid` char(40) NOT NULL COMMENT 'User ID',
  `code` char(6) NOT NULL COMMENT 'Verification code',
  `timestamp` datetime DEFAULT NULL COMMENT 'Validation code timestamp',
  PRIMARY KEY (`userid`),
  UNIQUE KEY `code` (`code`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii COMMENT='Verification codes';

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
