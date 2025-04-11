import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import cookie from 'cookie';
import signature from 'cookie-signature';
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

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 8080;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, 'uploads');
const IPAddress = 'ip goes here';

const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});


const options = {
    key: fs.readFileSync('./certs/key.pem'),
    cert: fs.readFileSync('./certs/cert.pem')
};

const sessionMiddleware = session({
    secret: 'mySecretKey', 
    resave: false,
    saveUninitialized: false,
    cookie: {
       
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        path: '/'
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

//const httpsServer = https.createServer(options, app);
const wss = new WebSocketServer({ server });
const clients = new Set();
const rooms = new Map(); // In-memory map for active rooms

let dataMap = new Map();

function onSocketError(err) {
    console.error(err);
}

const beat = setInterval(function ping() {
    wss.clients.forEach(function each(ws) {
        console.log(`Heart is still beating`);
        if (ws.connected === false) {
            console.log(`Heart has stopped beating`);
            return ws.terminate();
        }
        ws.connected = false;
        ws.ping();
    });
}, 30000);



app.use(cookieParser());
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './Client')));
app.use(express.static('./Client'));
app.use('/uploads', express.static(uploadDir));
app.use(limiter);
app.use(cors({
  origin: 'https://securechatproject.onrender.com', 
  credentials: true
}));



/* --------- Authentication Routes --------- */
app.post('/signup', async (req, res) => {
    let { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: "Missing username or password" });
    }
    
    // Force lowercase username
    username = username.toLowerCase();
    
    try {
        const hashedPassword = hashFun(password, true);
        
        // Check for existing user with this username
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
    
    // Force lowercase username
    username = username.toLowerCase();
    
    try {
        const hashedPassword = hashFun(password, true);
        console.log(username);
        console.log(hashedPassword);
        
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
        
        req.session.username = username;
        req.session.userId = user.userId;
        console.log('Session saved for:', req.session);
        return res.json({ success: true, redirect: 'https://securechatproject.onrender.com/menu.html' });
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
  

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'Client', 'index.html'));
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
  

/* --------- Create/Load Room Endpoint --------- */
app.post('/createRoom', async (req, res) => {
    // Ensure the user is logged in
    if (!req.session.username || !req.session.userId) {
        return res.status(403).json({ success: false, message: "Not logged in" });
    }
    let { target } = req.body;
    if (!target) {
        return res.status(400).json({ success: false, message: "No target username provided" });
    }
    // Force lowercase on target username
    target = target.toLowerCase();
    try {
        // Look up the target user directly (no hashing)
        const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [target]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Target user not found" });
        }
        const targetUser = rows[0];
        const currentUserId = req.session.userId;
        const targetUserId = targetUser.userId;
        // Check if a room already exists between these two users
        const [roomRows] = await pool.query(
            "SELECT ru.roomId FROM room_users ru WHERE ru.userId IN (?, ?) GROUP BY ru.roomId HAVING COUNT(DISTINCT ru.userId) = 2",
            [currentUserId, targetUserId]
        );
        let roomId;
        if (roomRows.length > 0) {
            roomId = roomRows[0].roomId;
        } else {
            // Create new room: generate an encryption key
            const roomKey = crypto.randomBytes(32).toString('hex');
            const [roomResult] = await pool.query("INSERT INTO rooms (encryptionKey) VALUES (?)", [roomKey]);
            roomId = roomResult.insertId;
            // Associate both users with this room
            await pool.query("INSERT INTO room_users (roomId, userId) VALUES (?, ?)", [roomId, currentUserId]);
            await pool.query("INSERT INTO room_users (roomId, userId) VALUES (?, ?)", [roomId, targetUserId]);
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

/* --------- WebSocket Server --------- */
wss.on('connection', (ws, request) => {
    console.log(request);
    const username = request.session.username;

    // request.room is an object with roomId and encryptionKey from our upgrade handler
    const room = request.room || { roomId: 'public', encryptionKey: null };

    ws.room = room;
    ws.username = username;
    clients.add(ws);

    // Add connection to in-memory room set
    if (!rooms.has(room.roomId)) {
        rooms.set(room.roomId, new Set());
    }
    rooms.get(room.roomId).add(ws);
    
    ws.connected = true;
    
    // Load and send chat history for the room (decrypting messages)
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
              console.error("Decryption error:", e);
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
    ws.on('error', console.error);
    
    ws.on('message', async (newData) => {
        console.log("Received data");
        const str = newData.toString('utf8');
        let jsonCheck = false;
        let parsed;
        try {
            parsed = JSON.parse(str);
            jsonCheck = true;
        } catch (err) {
            console.log("Data is not valid JSON");
        }
        
        // If file metadata is received, save it
        if (jsonCheck && parsed.type === 'file') {
            dataMap.set(ws, parsed);
            return;
        }
        
        // If binary data (file) is received
        if (!jsonCheck && Buffer.isBuffer(newData)) {
            console.log("Processing file binary data");
            const metadata = dataMap.get(ws);
            if (!metadata) {
                console.log("No file metadata found");
                return;
            }
            const newFileName = metadata.fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
            const filePath = path.join(uploadDir, newFileName);
            fs.writeFileSync(filePath, newData);
            console.log(`File saved: ${filePath}`);
            const fileURL = `https://${IPAddress}:8080/uploads/${newFileName}`;
            const fileData = {
                type: 'file',
                fileName: newFileName,
                sender: username,
                url: fileURL,
                date: metadata.date
            };
            
            // Broadcast file message to clients in the same room
            rooms.get(room.roomId).forEach(client => {
                if (client.readyState === client.OPEN) {
                    client.send(JSON.stringify(fileData));
                }
            });
            
            // Save file message to the database
            try {
              await pool.query(
                "INSERT INTO messages (room, sender, type, content, date, fileName, url) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [room.roomId, username, 'file', '', metadata.date, newFileName, fileURL]
              );
            } catch(err) {
              console.error("Error saving file message:", err);
            }
            dataMap.delete(ws);
            return;
        }
        
        // Process text messages
        if (jsonCheck) {
            if (parsed.type === 'message') {
                console.log(`Room: ${room.roomId} | (${parsed.date}) ${username}: ${parsed.data}`);
                // Broadcast the message to clients in the room
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
                // Encrypt message before storing if encryption key exists
                let encryptedText = parsed.data;
                if (room.encryptionKey) {
                    try {
                      encryptedText = encryptMessage(parsed.data, room.encryptionKey);
                    } catch (e) {
                      console.error("Encryption error:", e);
                    }
                }
                // Save the message to the database
                try {
                  await pool.query(
                    "INSERT INTO messages (room, sender, type, content, date) VALUES (?, ?, ?, ?, ?)",
                    [room.roomId, username, 'message', encryptedText, parsed.date]
                  );
                } catch(err) {
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

server.on('upgrade', function upgrade(request, socket, head) {
    // Parse cookies from the header
    console.log('TTHIS IS SPARTA:', request);
    const cookies = cookie.parse(request.headers.cookie || '');
    const rawCookie = cookies['session']; // use your cookie name if different

    if (!rawCookie) {
        console.log("No session cookie found");
        socket.destroy();
        return;
    }

    // Unsign the cookie. Cookie-session typically prefixes the cookie value with 's:'
    let sessionData;
    if (rawCookie.startsWith('s:')) {
        const unsigned = signature.unsign(rawCookie.slice(2), 'mySecretKey');
        if (!unsigned) {
        console.log("Session cookie signature invalid");
        socket.destroy();
        return;
        }
        try {
        sessionData = JSON.parse(unsigned);
        } catch (err) {
        console.error("Error parsing session cookie:", err);
        socket.destroy();
        return;
        }
    } else {
        try {
        sessionData = JSON.parse(rawCookie);
        } catch (err) {
        console.error("Error parsing session cookie:", err);
        socket.destroy();
        return;
        }
    }

    // Check if session data has the expected properties
    if (!sessionData.username || !sessionData.userId) {
        console.log("Unauthorized WebSocket request - Invalid session data");
        socket.destroy();
        return;
    }


    request.session = sessionData;

    const urlParams = new URLSearchParams(request.url.split('?')[1]);
    const token = urlParams.get('token');
    const roomId = urlParams.get('room'); // expecting room id

    if (token !== 'mysecrettoken' || !roomId) {  
        console.log("Unauthorized or missing room parameter");
        socket.destroy();
        return;
    }

    sessionMiddleware(request, {}, async () => {
        if (!request.session.username) {
            console.log("Unauthorized WebSocket request - No username in session");
            socket.destroy();
            return;
        }
        // Validate that the user is associated with the room
        const roomRecord = await getRoomForUser(roomId, request.session.userId);
        if (!roomRecord) {
            console.log("User is not authorized for this room");
            console.log(roomId);
            console.log(request.session.userId);
            socket.destroy();
            return;
        }
        // Attach the room record (with roomId and encryptionKey) to the request
        request.room = roomRecord;
        
        wss.handleUpgrade(request, socket, head, function done(ws) {
            wss.emit('connection', ws, request);
        });
    });
});

// httpsServer.listen(PORT, '0.0.0.0', () => {
//     console.log('Secure WebSocket Server running on **********');
// });

async function getUserByUsername(username) {
    // Ensure username is lowercase before query
    username = username.toLowerCase();
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    return rows;
}

getUserByUsername('admin')
    .then(rows => {
        console.log(rows);
    })
    .catch(err => {
        console.error(err);
    });