import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import session from 'cookie-session';
import bodyParser from 'body-parser';
import hashFun from './src/hash.js';
import express from 'express';
import https from 'https';
import path from 'path';
import fs from 'fs';
import pool from './DB.js';
import crypto from 'crypto';
import cors from 'cors';
import cookie from 'cookie';
import signature from 'cookie-signature';

// Setup basic variables and Express app.
const app = express();
const PORT = process.env.PORT || 8080;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, 'uploads');
const IPAddress = 'ip goes here'; // Adjust as needed.

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

// Configure cookie-session middleware.
const sessionSecret = '622ce618f28e8182d5d8b35395b90195ae4de8ff6b45bb46adb98ada0647b600';
const sessionMiddleware = session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,            // Set to true for HTTPS.
    httpOnly: true,
    sameSite: 'none',        // For cross-site usage; adjust if on the same domain.
    path: '/',
    maxAge: 24 * 60 * 60 * 1000 // 1 day expiration.
  }
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many messages, You are on timeout'
});

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(cookieParser());
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './Client')));
app.use(express.static('./Client'));
app.use('/uploads', express.static(uploadDir));
app.use(limiter);
app.use(cors({
  origin: 'https://securechatproject.onrender.com', 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, './Client', 'index.html'));
});

/* --------- Authentication Routes --------- */

app.post('/signup', async (req, res) => {
  let { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  // Force lowercase.
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
    // Save session data; cookie-session stores these in a cookie.
    req.session.username = username;
    req.session.userId = user.userId;
    console.log("Session saved for:", req.session);
    return res.json({ success: true, redirect: 'menu.html' });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.post('/index', (req, res) => {
  let { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: "Missing username or password" });
  } else {
    username = username.toLowerCase();
    const hashPass = hashFun(password, true);
    console.log(`Username: ${username}`);
    console.log(`Password Hash: ${hashPass}`);
  }
  req.session.username = username;
  res.json({ success: true });
});

app.get('/api/session-check', (req, res) => {
  if (req.session.username) {
    return res.json({ loggedIn: true, username: req.session.username });
  } else {
    return res.status(401).json({ loggedIn: false });
  }
});
  
app.get('/chat', (req, res) => {
  if (!req.session.username) {
    return res.status(403).send("Access Denied. Please login.");
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/', (req, res) => {
  res.send("Nothing to see here...");
});

app.get('/debug-session', (req, res) => {
  res.json({
    session: req.session,
    cookies: req.headers.cookie
  });
});

app.post('/createRoom', async (req, res) => {
  if (!req.session.username || !req.session.userId) {
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
    const currentUserId = req.session.userId;
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
const wss = new WebSocketServer({ server });
const clients = new Set();
const rooms = new Map(); // In-memory map for active rooms
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

wss.on('connection', (ws, request) => {
  if (!request.session || !request.session.username) {
    console.error("Connection error: No session data on request");
    ws.close();
    return;
  }
  
  const username = request.session.username;
  const room = request.room || { roomId: 'public', encryptionKey: null };
  
  ws.room = room;
  ws.username = username;
  clients.add(ws);
  
  if (!rooms.has(room.roomId)) {
    rooms.set(room.roomId, new Set());
  }
  rooms.get(room.roomId).add(ws);
  
  ws.connected = true;
  
  // Debug: Log that the connection has been made.
  console.log(`WebSocket connected: user ${username} in room ${room.roomId}`);
  
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
      
      rooms.get(room.roomId).forEach(client => {
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
        rooms.get(room.roomId).forEach(client => {
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
    if (rooms.has(room.roomId)) {
      rooms.get(room.roomId).delete(ws);
      if (rooms.get(room.roomId).size === 0) {
        rooms.delete(room.roomId);
      }
    }
  });
});

// --- Helper function to decode Base64 session data ---
function decodeSession(rawValue) {
  try {
    const jsonStr = Buffer.from(rawValue, 'base64').toString('utf8');
    return JSON.parse(jsonStr);
  } catch (err) {
    console.error("Error decoding session:", err);
    return null;
  }
}

// --- WebSocket Upgrade Handler: Manually Extract and Validate Cookie-Session Data ---
server.on('upgrade', function upgrade(request, socket, head) {
  console.log("Upgrade request received:", request.url);
  console.log("Upgrade: Incoming cookie header:", request.headers.cookie);
  
  // Parse cookies from the request header.
  const cookies = cookie.parse(request.headers.cookie || '');
  console.log("Upgrade: Parsed cookies:", cookies);
  
  if (!cookies.session) {
    console.log("Upgrade: No session cookie found");
    socket.destroy();
    return;
  }
  
  const rawCookie = cookies['session'];       // Base64 encoded session data.
  const rawCookieSig = cookies['session.sig'];  // The stored session signature.
  
  console.log("Upgrade: rawCookie:", rawCookie);
  console.log("Upgrade: rawCookieSig:", rawCookieSig);
  
  if (!rawCookie || !rawCookieSig) {
    console.log("Upgrade: Missing session cookie or signature");
    socket.destroy();
    return;
  }
  
  // Compute the expected full signature using our secret.
  const secretBuffer = Buffer.from(sessionSecret, 'utf8');
  const fullSigned = signature.sign(rawCookie, sessionSecret);
  // Extract the hash portion (after the "s:" prefix or period).
  let expectedHash = fullSigned.split('.')[1];

  expectedHash = expectedHash.replace(/\+/g, '-').replace(/\//g, '_');
  console.log("Upgrade: Computed expectedHash:", expectedHash);
  
  if (rawCookieSig !== expectedHash) {
    console.log("Upgrade: Invalid session cookie signature");
    socket.destroy();
    return;
  }
  
  // Decode the Base64-encoded session data.
  const sessionData = decodeSession(rawCookie);
  if (!sessionData) {
    console.log("Upgrade: Failed to decode session data");
    socket.destroy();
    return;
  }
  console.log("Upgrade: Decoded session data:", sessionData);
  
  // Attach session data to the upgrade request.
  request.session = sessionData;
  
  // Validate query parameters (e.g., room).
  const urlParams = new URLSearchParams(request.url.split('?')[1]);
  const roomId = urlParams.get('room');
  if (!roomId) {
    console.log("Upgrade: Missing room parameter");
    socket.destroy();
    return;
  }
  
  // Validate that the user is allowed in the room.
  getRoomForUser(roomId, request.session.userId)
    .then(roomRecord => {
      if (!roomRecord) {
        console.log(`Upgrade: User ${request.session.userId} is not authorized for room ${roomId}`);
        socket.destroy();
        return;
      }
      console.log("Upgrade: User is authorized for room", roomId, "with roomRecord:", roomRecord);
      request.room = roomRecord;
      
      // Complete the WebSocket upgrade.
      wss.handleUpgrade(request, socket, head, function done(ws) {
        console.log("Upgrade: WebSocket connection successfully established.");
        wss.emit('connection', ws, request);
      });
    })
    .catch(err => {
      console.error("Upgrade: Error during room validation:", err);
      socket.destroy();
    });
});
