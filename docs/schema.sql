-- phpMyAdmin SQL Dump
-- version 3.4.11.1deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generato il: Mar 07, 2013 alle 15:04
-- Versione del server: 5.5.28
-- Versione PHP: 5.4.4-14

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
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
-- Struttura della tabella `presence`
--

CREATE TABLE `presence` (
  `userid` varchar(48) NOT NULL,
  `timestamp` datetime NOT NULL,
  `status` varchar(500) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `show` varchar(30) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `priority` smallint(5) NOT NULL DEFAULT '0' COMMENT 'Priority',
  PRIMARY KEY (`userid`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii;

-- --------------------------------------------------------

--
-- Struttura della tabella `push`
--

CREATE TABLE `push` (
  `userid` varchar(48) CHARACTER SET ascii NOT NULL,
  `provider` varchar(10) COLLATE ascii_bin NOT NULL,
  `registration_id` text COLLATE ascii_bin NOT NULL,
  PRIMARY KEY (`userid`,`provider`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii COLLATE=ascii_bin COMMENT='Push notification registrations';

-- --------------------------------------------------------

--
-- Struttura della tabella `servers`
--

CREATE TABLE `servers` (
  `fingerprint` char(40) NOT NULL COMMENT 'Server key fingerprint',
  `host` varchar(100) NOT NULL COMMENT 'Server address',
  PRIMARY KEY (`fingerprint`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii COMMENT='Servers';

-- --------------------------------------------------------

--
-- Struttura della tabella `stanzas`
--

CREATE TABLE `stanzas` (
  `id` varchar(30) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'Stanza ID',
  `sender` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'From',
  `recipient` varchar(48) CHARACTER SET ascii NOT NULL COMMENT 'To',
  `content` mediumblob NOT NULL COMMENT 'Stanza content',
  `timestamp` bigint(20) unsigned NOT NULL COMMENT 'Stanza timestamp',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='Pending stanzas';

-- --------------------------------------------------------

--
-- Struttura della tabella `validations`
--

CREATE TABLE `validations` (
  `userid` char(48) NOT NULL COMMENT 'User ID',
  `code` char(6) NOT NULL COMMENT 'Verification code',
  `timestamp` datetime DEFAULT NULL COMMENT 'Validation code timestamp',
  PRIMARY KEY (`userid`),
  UNIQUE KEY `code` (`code`)
) ENGINE=MyISAM DEFAULT CHARSET=ascii COMMENT='Verification codes';

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
