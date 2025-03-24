-- MySQL dump 10.13  Distrib 8.0.41, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: chatdb
-- ------------------------------------------------------
-- Server version	9.2.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `auth`
--

DROP TABLE IF EXISTS `auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth` (
  `authId` int NOT NULL AUTO_INCREMENT,
  `password` varchar(1000) DEFAULT NULL,
  `userId` int NOT NULL,
  PRIMARY KEY (`authId`),
  KEY `userId_idx` (`userId`),
  CONSTRAINT `userId` FOREIGN KEY (`userId`) REFERENCES `users` (`userId`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth`
--

LOCK TABLES `auth` WRITE;
/*!40000 ALTER TABLE `auth` DISABLE KEYS */;
INSERT INTO `auth` VALUES (7,'622ce618f28e8182d5d8b35395b90195ae4de8ff6b45bb46adb98ada0647b600',9),(8,'67e34854f3960acd4c8f8d906acf29f05978abfbc7a46a1574e80b2b0f54601b',10),(9,'8900b30b43729de19b47ff23965463e579b23dfbeb07db0695bc06c845892be2',11),(10,'0c62d7172a1af6db622dcda60f576c4ed96bc18704a0eba5d8490225e04e5d9d',12);
/*!40000 ALTER TABLE `auth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `messages` (
  `id` int NOT NULL AUTO_INCREMENT,
  `room` int NOT NULL,
  `sender` varchar(255) NOT NULL,
  `type` varchar(50) NOT NULL,
  `content` text,
  `fileName` varchar(255) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `date` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `room_idx` (`room`),
  CONSTRAINT `room` FOREIGN KEY (`room`) REFERENCES `rooms` (`roomId`)
) ENGINE=InnoDB AUTO_INCREMENT=54 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `messages`
--

LOCK TABLES `messages` WRITE;
/*!40000 ALTER TABLE `messages` DISABLE KEYS */;
INSERT INTO `messages` VALUES (7,2,'apple','message','8fca0859f755edf5c24ba3f3811b357b:18f1de508278a93bbe6837fce11e799da041a9a46834de909ecb4a2113d669d35a6b1ea4cf66a053674246fd25216a520c112daefdf03fd03426cd94eea62f6c',NULL,NULL,'3/23/2025, 2:47:08 PM'),(8,2,'apple','message','45b107e56c687aa6c2937bec9e6aab30:f85f31a76077c12b64e21fedf9e344e9',NULL,NULL,'3/23/2025, 2:47:29 PM'),(9,2,'apple','file','','Midterm_1_Slides-1.pdf','https://192.168.56.1:8080/uploads/Midterm_1_Slides-1.pdf','3/23/2025, 2:47:41 PM'),(10,2,'pear','message','7dd637328dba2f9fdd46f88e43c51045:d609212d3a77017b9ee45ee70687588fedf4f66a5377aada89ae10f922d0321aa2c667ef3976658016950b19dcb2097411fb769309b52ac70546ae8e80ba4ff2',NULL,NULL,'3/23/2025, 2:48:22 PM'),(11,3,'noah','message','0cbce5b1810927eaa8bfe121495612a3:be1a32a6ccb650c28a3b1b0c0542e0300d654a383f195c52c813115353841c5ff536bb64ad80f07e01356ccace98037f',NULL,NULL,'3/23/2025, 2:49:56 PM'),(12,3,'noah','message','447bef44c206cfa89957e7b623d68e6e:5997249af81dc9e63a2e38f1aa859fd88b5b7833fce9c14c820d7d2b945b53c9e0646169370a26498643dacb63589161d09ba368acfa7a8345f9a51e5aec574a',NULL,NULL,'3/23/2025, 3:10:46 PM'),(13,3,'noah','message','d30e10ad6e4eb1d32e65a3f540656f98:db706715036bf313bd6b57daeaba85cb9aba4503233064751adeb996ecce58aa',NULL,NULL,'3/23/2025, 3:12:27 PM'),(14,3,'noah','message','354251cc9e564bf2e40a32c7d61ba4b7:c271a276d6e06bf2b739ec4a597ce0857371239202ea28356e9c4e30993702f756c41b1669ef3e4ab07e097c52286740',NULL,NULL,'3/23/2025, 3:14:34 PM'),(15,3,'noah','message','14531531e3e871ad2477231c277b3368:5c9928330af7b98b24cda004aa06ba34',NULL,NULL,'3/23/2025, 3:30:21 PM'),(16,3,'noah','message','26a75e723848269eb9008ec39e459ea5:8511b72a16b3885f856c70f4243e207d',NULL,NULL,'3/23/2025, 3:30:23 PM'),(17,3,'noah','message','839046be1143d08391d71fd73fa2d93c:1df2344b7286df3fd3451e68581efd63',NULL,NULL,'3/23/2025, 3:30:26 PM'),(18,3,'noah','message','b7d7a168af79831ac501006ca9e0df08:97de4e76289e43f6431a3d72bba7235f',NULL,NULL,'3/23/2025, 3:30:31 PM'),(19,3,'noah','message','c77f6b362040287acfda2b60c69083ea:0e7d1881149902072ae53eba7136151f',NULL,NULL,'3/23/2025, 3:44:15 PM'),(20,3,'noah','message','2a8874d9692fe103eaf36afc9a8a77d9:d64157cb43c3ed7c92d419ff8c6a99a477c802ae2fa503ac4d735238d40e6d7c26cdf5a575da32522e0f24c519a987be',NULL,NULL,'3/23/2025, 3:47:32 PM'),(21,3,'noah','message','98f11693cd523aef52ea6760bfb49ae7:fc6f2da4b574ae04073164f182212a01a4929c83bd86f6864997a5126d19c187',NULL,NULL,'3/23/2025, 3:57:43 PM'),(22,3,'noah','message','2fb4d9af2d015501cf392b89c7b4de28:ab0343abde57d6a759233b1f2a0d6ccc',NULL,NULL,'3/23/2025, 3:57:46 PM'),(23,3,'noah','message','aea29ab8b0420f8ab03054abb5ac80b9:ad553d6160f2fa7971aa964ee8582ef6',NULL,NULL,'3/23/2025, 3:57:48 PM'),(24,3,'noah','message','246a6c568f6156a48dbb37ab90445376:ea9cc087c40cbdbba6d04e75c6f01ed6',NULL,NULL,'3/23/2025, 3:57:51 PM'),(25,3,'noah','message','1c42fb4535fffbc809b0a23338211212:cf93684601572d9c0a5b497ca483d9b5',NULL,NULL,'3/23/2025, 3:57:52 PM'),(26,3,'noah','message','80b2ef155d1e098b49a4b928968782d4:56e7b3a08fa876cc29606d52254a4c04',NULL,NULL,'3/23/2025, 3:57:54 PM'),(27,3,'noah','message','9500fe79f2ea1dbe3409d231dd189a57:8ba3ea45bf417ed195e394fca3413e57',NULL,NULL,'3/23/2025, 3:57:56 PM'),(28,3,'noah','message','f96b3d0aef73c8cf6c983dda7f90fa04:360a0c40b702581466c52e3613873719',NULL,NULL,'3/23/2025, 3:57:58 PM'),(29,3,'noah','message','6d559db8e9636c11175319e9b725f0d0:f661d6773e6386e162e9a71bd1e93dea7714c93edbc995a0bac41d9f372a0efd',NULL,NULL,'3/23/2025, 3:59:45 PM'),(30,3,'noah','file','','Incident_Report_Noah_Scott.docx','https://192.168.56.1:8080/uploads/Incident_Report_Noah_Scott.docx','3/23/2025, 4:00:05 PM'),(31,3,'pear','message','b1be3d99dc5ed2854f784d5086ea238e:d087b9ce3c396f137d89de254199db9c04a9a4d7c4799149378a5935ebe8a88a',NULL,NULL,'3/23/2025, 4:00:48 PM'),(32,4,'garry','message','49ee7d426b1ec6276e28c3a6b84369c3:47ce2b2b59d446efef880a16137e85953730e474281ecf9f673cb81673bc6fa8',NULL,NULL,'3/23/2025, 4:04:56 PM'),(33,3,'noah','message','d4ae2312145a1950191f6fa9b9bf2bb8:b23c73f10812933f4b4031c24b42d7970a9671333e3c06bbbc5a2a58bbdd68e71cc603186147d8c2c26500750475c23d688e5516ea5fd2e42c4da1a68aab1c22',NULL,NULL,'3/23/2025, 4:15:06 PM'),(34,3,'pear','message','a86ddb70d76617ae965ab7bb40e47eb9:741dd71dce957bbfcddf9f97b265129a42b758aaa559b657dd5a96f6d55c18bc',NULL,NULL,'3/23/2025, 4:22:21 PM'),(35,3,'noah','message','05cce17049941603f2a948d3083446a0:98d16b22ca7f5d2e6823ad8965d6e761345bfa687f7dec8fc5ed656f1113bb4c302fcd69be3b3f721977ff6b87667b1b',NULL,NULL,'3/23/2025, 4:22:37 PM'),(36,5,'pear','message','1cdf5b48e3cd4bc5d7c65cbdc5b54bb2:44478d4ed37e34690663da5c326f185eb11dea4d51d8352b403ecabfafb0189b',NULL,NULL,'3/23/2025, 4:24:19 PM'),(37,5,'garry','message','7150d3addc5d77c76900b2933c123bb0:46315b8d202be435010a5b5cfa62ae0485ad6f6cc42fa21ab015b51ce40a81bf',NULL,NULL,'3/23/2025, 4:26:43 PM'),(38,5,'garry','message','0eccfe4271b0c5d6397613cf469d47ff:2e4ed96854084b3403ca730e0bc8d049fedd039c5d911b08a35c8de0abb6fd3e',NULL,NULL,'3/23/2025, 4:26:57 PM'),(39,3,'noah','message','02b90d11e5e109dbbecbabbcd608a955:7a388df6dcaaed25143a0e2ae4fa4ca60c6dcb8a49dacb90bd93d6ebd3d7f667',NULL,NULL,'3/23/2025, 4:35:59 PM'),(40,3,'pear','message','c84d9575b9845d32908581f393dd0ffe:57769c2421712812bf37c45f045b5fe9',NULL,NULL,'3/23/2025, 4:36:23 PM'),(41,5,'garry','message','d0e010921fa6be7d93a2b078e4155257:0b0c77a018586043c8cb13d4d9fd18e3d03854ceab53c0c89ce38a20babd3926',NULL,NULL,'3/23/2025, 4:36:58 PM'),(42,2,'apple','message','ae155256572f6ad9db2e3d80a027c3ac:6c1c9fa7e2d018b6f903998e34c9d49c',NULL,NULL,'3/23/2025, 6:14:35 PM'),(43,2,'pear','message','20d74afad59d6d47ecbae89b564aa462:9fda468d1ceb9a8c2eb06e31725f3089',NULL,NULL,'3/23/2025, 6:14:40 PM'),(44,2,'pear','file','','Noah_Scott_Class_Schedule.pdf','https://172.20.10.4:8080/uploads/Noah_Scott_Class_Schedule.pdf','3/23/2025, 6:16:58 PM'),(45,2,'pear','file','','e30c7934d05a995a4fc9b7fa8df57942.png','https://172.20.10.4:8080/uploads/e30c7934d05a995a4fc9b7fa8df57942.png','3/23/2025, 6:34:16 PM'),(46,2,'pear','file','','bulb.gif','https://172.20.10.4:8080/uploads/bulb.gif','3/23/2025, 6:34:26 PM'),(47,2,'pear','file','','tenor.gif','https://172.20.10.4:8080/uploads/tenor.gif','3/23/2025, 6:38:17 PM'),(48,2,'pear','message','eb80894098803eec738995804c7ec3fc:faf2d54acb10ad9e83cd16aafc0a7e41',NULL,NULL,'3/23/2025, 6:38:45 PM'),(49,2,'pear','message','617695d33baf317fd0ac3c2ba9de96e1:c5872eccb674788e82e0bdd335166ea2',NULL,NULL,'3/23/2025, 6:41:33 PM'),(50,2,'pear','message','17a8eb2db97d45a7d11225eadce7cf1a:7cec9f626ec2fbb5fe1d5f7193e2ea03',NULL,NULL,'3/23/2025, 6:41:35 PM'),(51,5,'pear','message','c9822433e3d74474a2105776e8407f96:472157e684baa94556a46915c6cde00b',NULL,NULL,'3/23/2025, 6:42:08 PM'),(52,5,'pear','message','ed1eb0c9192794da27f20eb6ccaa7cbf:c2f31b405d3f75eaeeaa4e8e0bb2d8c4',NULL,NULL,'3/23/2025, 6:42:15 PM'),(53,5,'pear','message','2a0621764a06ace0c7d40c540360f073:8f71ca6d411adb16cdedf4d1c61622e7',NULL,NULL,'3/23/2025, 6:42:54 PM');
/*!40000 ALTER TABLE `messages` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `room_users`
--

DROP TABLE IF EXISTS `room_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `room_users` (
  `roomId` int NOT NULL,
  `userId` int NOT NULL,
  PRIMARY KEY (`roomId`,`userId`),
  KEY `userId` (`userId`),
  CONSTRAINT `room_users_ibfk_1` FOREIGN KEY (`roomId`) REFERENCES `rooms` (`roomId`),
  CONSTRAINT `room_users_ibfk_2` FOREIGN KEY (`userId`) REFERENCES `users` (`userId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `room_users`
--

LOCK TABLES `room_users` WRITE;
/*!40000 ALTER TABLE `room_users` DISABLE KEYS */;
INSERT INTO `room_users` VALUES (2,9),(2,10),(3,10),(5,10),(3,11),(4,11),(4,12),(5,12);
/*!40000 ALTER TABLE `room_users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `rooms`
--

DROP TABLE IF EXISTS `rooms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `rooms` (
  `roomId` int NOT NULL AUTO_INCREMENT,
  `encryptionKey` varchar(64) NOT NULL,
  PRIMARY KEY (`roomId`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `rooms`
--

LOCK TABLES `rooms` WRITE;
/*!40000 ALTER TABLE `rooms` DISABLE KEYS */;
INSERT INTO `rooms` VALUES (2,'ea8ddd827e435a8026e20f8d7304269056101b281130480649135291d876f393'),(3,'8f0a61a1eb89093bc2b11d01a078cfc4e928c526a290785a68d4fc877ca86ce7'),(4,'486a2b3d0e387fda261f9a15dae932a5956362b42c32971f5f0714ecc2b0e136'),(5,'998f65d8c9abd99ebbd1fe199af64f63caf9f35404ee34096086231ef1415d16');
/*!40000 ALTER TABLE `rooms` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `userId` int NOT NULL AUTO_INCREMENT,
  `username` varchar(1000) DEFAULT NULL,
  `dateCreated` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`userId`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (9,'apple',NULL),(10,'pear',NULL),(11,'noah',NULL),(12,'garry',NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-03-23 18:49:40
