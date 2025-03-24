# Secure Chat WebSocket Server

## Overview
This WebSocket-based application allows users on the same network to communicate securely. It requires initial setup for both the MySQL database and the WebSocket server before running. Once configured, users can interact through a web-based chat interface.

## Table of Contents
- [Installation](#installation)
  - [MySQL Setup](#mysql-setup)
  - [Database Setup](#database-setup)
  - [WebSocket Server Setup](#websocket-server-setup)
- [Configuration](#configuration)
  - [Updating IP Addresses](#updating-ip-addresses)
- [Running the Program](#running-the-program)
- [Testing the Setup](#testing-the-setup)
- [Troubleshooting](#troubleshooting)

## Installation

### MySQL Setup
#### Windows
1. Download and install MySQL from [MySQL Installer](https://dev.mysql.com/downloads/installer/).
2. Choose **Developer Default** or **Server Only** during installation.
3. Follow on-screen instructions to complete setup, noting the root password.

#### macOS
1. Download MySQL DMG from [MySQL Downloads](https://dev.mysql.com/downloads/installer/).
2. Open the DMG file and run the installer.
3. Follow installation steps, optionally starting MySQL from System Preferences.

#### Linux (Ubuntu/Debian)
1. Open a terminal and run:
   ```bash
   sudo apt update
   sudo apt install mysql-server
   ```
2. Secure the installation:
   ```bash
   sudo mysql_secure_installation
   ```
3. Follow the prompts to set a root password.

### Database Setup
1. Open a terminal or MySQL Workbench and log in as root:
   ```bash
   mysql -u root -p
   ```
2. Create the `securechat` database:
   ```sql
   CREATE DATABASE securechat;
   EXIT;
   ```
3. Import the database schema:
   ```bash
   mysql -u root -p securechat < path/to/securechatdb.sql
   ```

Alternatively, using MySQL Workbench:
1. Connect to your MySQL server.
2. Create a new schema named `securechat`.
3. Navigate to **Server > Data Import** and import `securechatdb.sql`.

### WebSocket Server Setup
1. Install Node.js:
   - **Windows/macOS:** Download from [Node.js](https://nodejs.org/en/download/).
   - **Linux:** Run:
     ```bash
     sudo apt install nodejs npm
     ```
2. Navigate to the `Server` directory and install dependencies:
   ```bash
   npm install
   ```

## Configuration

### Updating IP Addresses
To connect to the WebSocket server, you need to update the IP address:
1. Find your public Wi-Fi IP:
   - **Windows:** Run `ipconfig` and look under **Wireless LAN Adapter Wi-Fi** > **IPv4**.
   - **Linux/macOS:** Run:
     ```bash
     curl -4 ifconfig.me
     ```
2. Update the following files:
   - **`chat.html` (line 39)**: Replace `127.0.0.1` with your IP.
   - **`Server.js` (line 20)**: Set `IPAddress = "your IP address here"`.

## Running the Program
1. Start the WebSocket server:
   ```bash
   npm start
   ```
   The terminal will indicate when the server is running.
2. Open a browser and navigate to:
   ```
   http://your-ip-address:8080
   ```
3. Accept the security warning and proceed.
4. Log in using your credentials and start chatting.
5. To stop the server, press **CTRL + C** in the terminal.

## Testing the Setup
1. Open the login page: `http://your-ip-address:8080?token=mytoken`.
2. Sign up or log in.
3. Start a chat session.
4. Verify messages are being sent and received.

## Troubleshooting
- If the server does not start, check that Node.js and MySQL are installed correctly.
- Ensure the correct root password is set in `DB.js`:
  ```js
  password: 'your_root_password'
  ```
- If database import fails, verify the file path to `securechatdb.sql`.

For additional support, refer to the [GitHub repository](https://github.com/xevanx2002/CPSC-455-Project-1).

