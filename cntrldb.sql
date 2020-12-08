-- MySQL dump 10.13  Distrib 5.7.32, for Linux (x86_64)
--
-- Host: localhost    Database: cntrldb
-- ------------------------------------------------------
-- Server version	5.7.32-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `CommunicatingPeers`
--

DROP TABLE IF EXISTS `CommunicatingPeers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CommunicatingPeers` (
  `Cid` int(11) NOT NULL AUTO_INCREMENT,
  `PID1` int(11) NOT NULL,
  `PID2` int(11) NOT NULL,
  `Status` varchar(20) DEFAULT NULL,
  `Communicating` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`Cid`),
  KEY `PID1` (`PID1`),
  KEY `PID2` (`PID2`),
  CONSTRAINT `CommunicatingPeers_ibfk_1` FOREIGN KEY (`PID1`) REFERENCES `ConfiguredPeers` (`id`),
  CONSTRAINT `CommunicatingPeers_ibfk_2` FOREIGN KEY (`PID2`) REFERENCES `ConfiguredPeers` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CommunicatingPeers`
--

LOCK TABLES `CommunicatingPeers` WRITE;
/*!40000 ALTER TABLE `CommunicatingPeers` DISABLE KEYS */;
/*!40000 ALTER TABLE `CommunicatingPeers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ConfiguredPeers`
--

DROP TABLE IF EXISTS `ConfiguredPeers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ConfiguredPeers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `Cryptoperiod` int(11) DEFAULT NULL,
  `PubKey1` varchar(100) DEFAULT NULL,
  `PubKey2` varchar(100) DEFAULT NULL,
  `Status` varchar(20) NOT NULL,
  `Compromised` bit(1) NOT NULL,
  `IPv4Addr` varchar(20) DEFAULT NULL,
  `IPv4AddrWG` varchar(20) DEFAULT NULL,
  `Dpid` varchar(30) NOT NULL,
  `Since` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ConfiguredPeers`
--

LOCK TABLES `ConfiguredPeers` WRITE;
/*!40000 ALTER TABLE `ConfiguredPeers` DISABLE KEYS */;
/*!40000 ALTER TABLE `ConfiguredPeers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ErrorLog`
--

DROP TABLE IF EXISTS `ErrorLog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ErrorLog` (
  `ErrId` int(11) NOT NULL AUTO_INCREMENT,
  `Dpid` varchar(30) NOT NULL,
  `Type` varchar(20) NOT NULL,
  `ErrCode` varchar(30) NOT NULL,
  `Attempt` int(11) NOT NULL,
  `Resolved` tinyint(1) NOT NULL DEFAULT '0',
  `Note` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`ErrId`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ErrorLog`
--

LOCK TABLES `ErrorLog` WRITE;
/*!40000 ALTER TABLE `ErrorLog` DISABLE KEYS */;
/*!40000 ALTER TABLE `ErrorLog` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-12-07 15:35:19
