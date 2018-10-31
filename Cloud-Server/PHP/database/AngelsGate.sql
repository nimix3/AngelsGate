-- phpMyAdmin SQL Dump
-- version 4.7.7
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Oct 13, 2018 at 08:42 AM
-- Server version: 10.1.35-MariaDB-cll-lve
-- PHP Version: 5.6.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `AngelsGateV2`
--

-- --------------------------------------------------------

--
-- Table structure for table `AuthTable`
--

CREATE TABLE `AuthTable` (
  `id` bigint(20) NOT NULL,
  `session` varchar(128) DEFAULT NULL,
  `handler` varchar(128) DEFAULT NULL,
  `token` varchar(128) DEFAULT NULL,
  `cantoken` varchar(128) DEFAULT NULL,
  `timetoken` varchar(32) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `identifier` varchar(256) DEFAULT NULL,
  `ivr` varchar(64) DEFAULT NULL,
  `hpub` text,
  `hpriv` text,
  `endpoint` varchar(256) DEFAULT NULL,
  `pubkey` varchar(2048) DEFAULT NULL,
  `myid` varchar(64) DEFAULT NULL,
  `offset` int(64) DEFAULT NULL,
  `label` int(128) DEFAULT NULL,
  `user` int(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `ChainTable`
--

CREATE TABLE `ChainTable` (
  `id` bigint(20) NOT NULL,
  `session` varchar(128) DEFAULT NULL,
  `req` varchar(256) DEFAULT NULL,
  `res` varchar(256) DEFAULT NULL,
  `count` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `rlimit` int(11) DEFAULT NULL,
  `seq` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `HashTable`
--

CREATE TABLE `HashTable` (
  `id` bigint(20) NOT NULL,
  `session` varchar(128) DEFAULT NULL,
  `ssalt` varchar(64) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `ip` varchar(32) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `IPTable`
--

CREATE TABLE `IPTable` (
  `id` bigint(20) NOT NULL,
  `ip` varchar(32) NOT NULL,
  `count` int(11) DEFAULT NULL,
  `total` bigint(20) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `block` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `AuthTable`
--
ALTER TABLE `AuthTable`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `ChainTable`
--
ALTER TABLE `ChainTable`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `HashTable`
--
ALTER TABLE `HashTable`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `IPTable`
--
ALTER TABLE `IPTable`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `AuthTable`
--
ALTER TABLE `AuthTable`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `ChainTable`
--
ALTER TABLE `ChainTable`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `HashTable`
--
ALTER TABLE `HashTable`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `IPTable`
--
ALTER TABLE `IPTable`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
