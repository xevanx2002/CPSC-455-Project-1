import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import hashFun from './src/hash.js';
import express from 'express';
import https from 'https';
import path from 'path';
import fs from 'fs';
import pool from './DB.js';
import crypto from 'crypto';
import cors from 'cors';
import jwt from 'jsonwebtoken';

// Setup basic variables and Express app.
const app = express();
const PORT = process.env.PORT || 8080;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, 'uploads');
const IPAddress = 'ip goes here'; // Adjust as needed.

// JWT secret (replace with a secure, randomly generated value in production)
const jwtSecret = 'myJWTSecret';

// Trust the proxy (for Render).
app.set('trust proxy', 1);

// Create the HTTP server.
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// HTTPS options (if needed)
// const options = {
//   key: fs.readFileSync('./certs/key.pem'),
//   cert: fs.readFileSync('./certs/cert.pem')
// };

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many messages, You are on timeout'
});

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './Client')));
app.use(express.static('./Client'));
app.use('/uploads', express.static(uploadDir));
app.use(limiter);
app.use(cors({
  origin: 'https://securechatproject.onrender.com', 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// For all other routes, serve the client.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, './Client', 'index.html'));
});

/* --------- Helper Middleware for JWT Verification on HTTP Endpoints --------- */
function verifyJWT(req, res, next) {
  // Expect the JWT in the Authorization header as "Bearer <token>"
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ success: false, message: "Missing Authorization header" });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

/* --------- Authentication Routes --------- */

app.post('/signup', async (req, res) => {
  let { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  username = username.toLowerCase();
  try {
    const hashedPassword = hashFun(password, true);
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ success: false, message: "Username already exists" });
    }
    const [userResult] = await pool.query('INSERT INTO users (username) VALUES (?)', [username]);
    if (!userResult.insertId) {
      return res.status(500).json({ success: false, message: "Signup failed at user insertion" });
    }
    const userId = userResult.insertId;
    const [authResult] = await pool.query('INSERT INTO auth (userId, password) VALUES (?, ?)', [userId, hashedPassword]);
    if (authResult.affectedRows === 1) {
      return res.json({ success: true, message: "Signup successful. Please log in." });
    } else {
      return res.status(500).json({ success: false, message: "Signup failed at auth insertion" });
    }
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.post('/login', async (req, res) => {
  let { username, password } = req.body;
  if (!username || !password) {
    console.log("Missing credentials");
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  username = username.toLowerCase();
  try {
    const hashedPassword = hashFun(password, true);
    console.log("Login attempt for:", username);
    console.log("Hashed password:", hashedPassword);
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      console.log("User not found");
      return res.status(401).json({ success: false, message: "Invalid username or password" });
    }
    const user = users[0];
    const [authRecords] = await pool.query('SELECT * FROM auth WHERE userId = ?', [user.userId]);
    if (authRecords.length === 0) {
      console.log("Auth record missing");
      return res.status(401).json({ success: false, message: "Invalid username or password" });
    }
    const authRecord = authRecords[0];
    if (hashedPassword !== authRecord.password) {
      console.log("Password mismatch");
      return res.status(401).json({ success: false, message: "Invalid username or password" });
    }
    // Issue a JWT token containing user info.
    const token = jwt.sign({ username, userId: user.userId }, jwtSecret, { expiresIn: '1d' });
    console.log("Login successful for:", username);
    return res.json({ success: true, token, redirect: 'menu.html' });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// An endpoint to check JWT token (protected).
app.get('/api/session-check', verifyJWT, (req, res) => {
  return res.json({ loggedIn: true, username: req.user.username });
});

// An example protected route for chat.
// This route expects a valid JWT in the Authorization header.
app.get('/chat', verifyJWT, (req, res) => {
  res.sendFile(path.join(__dirname, 'Client', 'chat.html'));
});

// For any other route.
app.get('/', (req, res) => {
  res.send("Nothing to see here...");
});

// /createRoom now protected by JWT middleware.
app.post('/createRoom', verifyJWT, async (req, res) => {
  // Now req.user holds the decoded JWT payload.
  if (!req.user || !req.user.userId) {
    return res.status(403).json({ success: false, message: "Not logged in" });
  }
  let { target } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, message: "No target username provided" });
  }
  target = target.toLowerCase();
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [target]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "Target user not found" });
    }
    const targetUser = rows[0];
    const currentUserId = req.user.userId;
    const [roomRows] = await pool.query(
      "SELECT ru.roomId FROM room_users ru WHERE ru.userId IN (?, ?) GROUP BY ru.roomId HAVING COUNT(DISTINCT ru.userId) = 2",
      [currentUserId, targetUser.userId]
    );
    let roomId;
    if (roomRows.length > 0) {
      roomId = roomRows[0].roomId;
    } else {
      const roomKey = crypto.randomBytes(32).toString('hex');
      const [roomResult] = await pool.query("INSERT INTO rooms (encryptionKey) VALUES (?)", [roomKey]);
      roomId = roomResult.insertId;
      await pool.query("INSERT INTO room_users (roomId, userId) VALUES (?, ?)", [roomId, currentUserId]);
      await pool.query("INSERT INTO room_users (roomId, userId) VALUES (?, ?)", [roomId, targetUser.userId]);
    }
    return res.json({ success: true, roomId });
  } catch (err) {
    console.error("Error in createRoom:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});





/* --------- Encryption Functions --------- */
const algorithm = 'aes-256-cbc';
function encryptMessage(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptMessage(encryptedData, key) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = parts.join(':');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

async function getRoomForUser(roomId, userId) {
  const [rows] = await pool.query(
    "SELECT r.roomId, r.encryptionKey FROM rooms r JOIN room_users ru ON r.roomId = ru.roomId WHERE r.roomId = ? AND ru.userId = ?",
    [roomId, userId]
  );
  return rows.length > 0 ? rows[0] : null;
}

/* --------- WebSocket Server Setup --------- */
const wss = new WebSocketServer({ noServer: true });
const clients = new Set();
const wsRooms = new Map(); // in-memory map for active rooms
let dataMap = new Map();

function onSocketError(err) {
  console.error(err);
}

const beat = setInterval(function ping() {
  wss.clients.forEach(function each(ws) {
    console.log("Heartbeat: checking client connection");
    if (ws.connected === false) {
      console.log("Heartbeat: client has stopped responding—terminating");
      return ws.terminate();
    }
    ws.connected = false;
    ws.ping();
  });
}, 30000);

function broadcastPresence(status, username, roomId) {
  const payload = {
    type: 'presence',
    status,
    username
  };

  const roomClients = wsRooms.get(roomId);
  if (roomClients) {
    roomClients.forEach(client => {
      if (client.readyState === client.OPEN) {
        // Skip notifying self, if desired
        if (client.user?.username !== username) {
          client.send(JSON.stringify(payload));
        }
      }
    });
  }
}


wss.on('connection', (ws, request) => {
  
  console.log("Connection event received, ws.user:", ws.user);
  
  // WebSocket connections now rely on JWT, so request.user is set in upgrade.
  if (!request.user || !request.user.username) {
    console.error("Connection error: No user data in token");
    ws.close();
    return;
  }
  
  const username = ws.user.username;
  const room = ws.room || { roomId: 'public', encryptionKey: null };
  
  // ws.room = room;
  // ws.username = username;
  clients.add(ws);
  
  if (!wsRooms.has(room.roomId)) {
    wsRooms.set(room.roomId, new Set());
  }
  wsRooms.get(room.roomId).add(ws);
  
  ws.connected = true;
  console.log(`WebSocket connected: user ${username} in room ${room.roomId}`);
  broadcastPresence('online', username, room.roomId);
  // Load chat history for the room.
  (async () => {
    try {
      const [messages] = await pool.query(
        "SELECT * FROM messages WHERE room = ? ORDER BY id ASC", 
        [room.roomId]
      );
      messages.forEach(message => {
        let content = message.content;
        if (message.type === 'message' && room.encryptionKey) {
          try {
            content = decryptMessage(message.content, room.encryptionKey);
          } catch (e) {
            console.error("Decryption error for message:", e);
          }
        }
        ws.send(JSON.stringify({
          type: message.type,
          sender: message.sender,
          date: message.date,
          data: content,
          fileName: message.fileName,
          url: message.url
        }));
      });
      console.log(`Loaded chat history for room: ${room.roomId}`);
    } catch (err) {
      console.error("Error loading chat history:", err);
    }
  })();
  
  ws.on('pong', () => { ws.connected = true; });
  
  ws.on('error', (err) => {
    console.error("WebSocket error:", err);
  });
  
  ws.on('message', async (newData) => {
    console.log("Received data on WebSocket");
    const str = newData.toString('utf8');
    let jsonCheck = false;
    let parsed;
    try {
      parsed = JSON.parse(str);
      jsonCheck = true;
    } catch (err) {
      console.log("Message is not valid JSON:", err);
    }
    
    if (jsonCheck && (parsed.type === 'typing' || parsed.type === 'stop_typing')) {
      const typingPayload = {
        type: parsed.type,
        username: ws.user.username
      };
    
      const roomClients = wsRooms.get(ws.room.roomId);
      if (roomClients) {
        roomClients.forEach(client => {
          if (client !== ws && client.readyState === client.OPEN) {
            client.send(JSON.stringify(typingPayload));
          }
        });
      }
      return;
    }
    
    if (jsonCheck && parsed.type === 'file') {
      dataMap.set(ws, parsed);
      return;
    }
    
    if (!jsonCheck && Buffer.isBuffer(newData)) {
      console.log("Processing file binary data");
      const metadata = dataMap.get(ws);
      if (!metadata) {
        console.log("No file metadata found for binary data");
        return;
      }
      const newFileName = metadata.fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
      const filePath = path.join(uploadDir, newFileName);
      fs.writeFileSync(filePath, newData);
      console.log(`File saved to ${filePath}`);
      const fileURL = `https://${IPAddress}:8080/uploads/${newFileName}`;
      const fileData = {
        type: 'file',
        fileName: newFileName,
        sender: username,
        url: fileURL,
        date: metadata.date
      };
      
      wsRooms.get(room.roomId).forEach(client => {
        if (client.readyState === client.OPEN) {
          client.send(JSON.stringify(fileData));
        }
      });

      
      
      try {
        await pool.query(
          "INSERT INTO messages (room, sender, type, content, date, fileName, url) VALUES (?, ?, ?, ?, ?, ?, ?)",
          [room.roomId, username, 'file', '', metadata.date, newFileName, fileURL]
        );
      } catch (err) {
        console.error("Error saving file message:", err);
      }
      dataMap.delete(ws);
      return;
    }
    
    if (jsonCheck) {
      if (parsed.type === 'message') {
        console.log(`Message from ${username} in room ${room.roomId}: ${parsed.data}`);
        wsRooms.get(room.roomId).forEach(client => {
          if (client.readyState === client.OPEN) {
            client.send(JSON.stringify({
              type: 'message',
              sender: username,
              date: parsed.date,
              data: parsed.data
            }));
          }
        });
        let encryptedText = parsed.data;
        if (room.encryptionKey) {
          try {
            encryptedText = encryptMessage(parsed.data, room.encryptionKey);
          } catch (e) {
            console.error("Encryption error for message:", e);
          }
        }
        try {
          await pool.query(
            "INSERT INTO messages (room, sender, type, content, date) VALUES (?, ?, ?, ?, ?)",
            [room.roomId, username, 'message', encryptedText, parsed.date]
          );
        } catch (err) {
          console.error("Error saving message:", err);
        }
      } else if (parsed.type === 'file') {
        dataMap.set(ws, parsed);
      }
    }
  });
  
  ws.on('close', () => {
    
    console.log(`${username} disconnected from room ${room.roomId}`);
    clients.delete(ws);
    if (wsRooms.has(room.roomId)) {
      wsRooms.get(room.roomId).delete(ws);
      if (wsRooms.get(room.roomId).size === 0) {
        wsRooms.delete(room.roomId);
      }
    }
    broadcastPresence('offline', ws.user.username, ws.room.roomId);
  });
});

/* --------- WebSocket Upgrade Handler using JWT --------- */
server.on('upgrade', function upgrade(request, socket, head) {
  console.log("SUSPECT SOCKET:", request.url);
  if (socket.upgraded) {
    console.log("Upgrade: Socket already upgraded. Ignoring duplicate upgrade.");
    socket.destroy();
    return;
  }
  console.log("Upgrade request received:", request.url);
  
  const urlParams = new URLSearchParams(request.url.split('?')[1]);
  const token = urlParams.get('token');
  const roomId = urlParams.get('room');
  
  if (!token || !roomId) {
    console.log("Upgrade: Missing token or room parameter");
    socket.destroy();
    return;
  }
  
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      console.log("Upgrade: JWT verification error:", err);
      socket.destroy();
      return;
    }
    console.log("Upgrade: Decoded JWT:", decoded);
    // Attach decoded JWT data to request.user.
    request.user = decoded;
    console.log("Upgraded: Attached request.user:", request.user, request.user.username);
    
    // Validate that the user is allowed in the room.
    getRoomForUser(roomId, decoded.userId)
      .then(roomRecord => {
        if (!roomRecord) {
          console.log(`Upgrade: User ${decoded.userId} is not authorized for room ${roomId}`);
          socket.destroy();
          return;
        }
        console.log("Upgrade: User is authorized for room", roomId, "with roomRecord:", roomRecord);
        request.room = roomRecord;
        
        // Complete the WebSocket upgrade.
        wss.handleUpgrade(request, socket, head, function done(ws) {
          socket.upgraded = true;
          
          ws.user = request.user;
          ws.room = request.room;

          console.log("Upgrade: WebSocket connection successfully established.");
          wss.emit('connection', ws, request);
        });
      })
      .catch(err => {
        console.error("Upgrade: Error during room validation:", err);
        socket.destroy();
      });
  });
});



