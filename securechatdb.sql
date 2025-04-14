-- securechatdb.sql
-- DROP existing tables if desired; be careful if you have existing data!
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS room_users;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS auth;
DROP TABLE IF EXISTS friend_requests;
DROP TABLE IF EXISTS friends;
DROP TABLE IF EXISTS users;

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    userId INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: auth (stores password hash)
CREATE TABLE IF NOT EXISTS auth (
    authId INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_auth_user FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);

-- Table: rooms (chat rooms with an encryption key)
CREATE TABLE IF NOT EXISTS rooms (
    roomId INT AUTO_INCREMENT PRIMARY KEY,
    encryptionKey VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: room_users (maps chat rooms to user members)
CREATE TABLE IF NOT EXISTS room_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomId INT NOT NULL,
    userId INT NOT NULL,
    CONSTRAINT fk_room FOREIGN KEY (roomId) REFERENCES rooms(roomId) ON DELETE CASCADE,
    CONSTRAINT fk_room_user FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);

-- Table: messages (stores chat messages and file messages)
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    room INT NOT NULL,
    sender VARCHAR(255) NOT NULL,
    type ENUM('message', 'file') DEFAULT 'message',
    content TEXT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    fileName VARCHAR(255),
    url VARCHAR(255),
    CONSTRAINT fk_messages_room FOREIGN KEY (room) REFERENCES rooms(roomId) ON DELETE CASCADE
);

-- Table: friend_requests (stores pending, accepted, or rejected friend requests)
CREATE TABLE IF NOT EXISTS friend_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fromUserId INT NOT NULL,
    toUserId INT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_fr_fromUser FOREIGN KEY (fromUserId) REFERENCES users(userId) ON DELETE CASCADE,
    CONSTRAINT fk_fr_toUser FOREIGN KEY (toUserId) REFERENCES users(userId) ON DELETE CASCADE,
    UNIQUE KEY unique_friend_request (fromUserId, toUserId)
);

-- Table: friends (stores established friendships)
CREATE TABLE IF NOT EXISTS friends (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    friendId INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_friends_user FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE,
    CONSTRAINT fk_friends_friend FOREIGN KEY (friendId) REFERENCES users(userId) ON DELETE CASCADE,
    UNIQUE KEY unique_friendship (userId, friendId)
);
