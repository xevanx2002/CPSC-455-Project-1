import { WebSocketServer } from 'ws';
import express from 'express';
import session from 'express-session';
import https from 'https';
import fs from 'fs';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import { parse } from 'cookie';

const app = express();
const PORT = process.env.PORT || 8080;


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const sessionMiddleware = session({
    secret: 'mySecretKey', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
});

app.use(sessionMiddleware);
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './Client')));

app.post('/index', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Missing username or password" });
    }

    // Store username in session
    req.session.username = username;

    res.json({ success: true });
});

app.get('/chat', (req, res) => {
    if (!req.session.username) {
        return res.status(403).send("Access Denied. Please login.");
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const options = {
    key: fs.readFileSync('./certs/key.pem'),
    cert: fs.readFileSync('./certs/cert.pem')
};


// const httpServer = app.listen(PORT, '0.0.0.0',() => {
//     console.log('yuh baby girl les gooooo');
// });
const httpsServer = https.createServer(options, app);
const wss = new WebSocketServer({ noServer: true});

const clients = new Set();

function onSocketError(err) {
    console.error(err);
};

function heartBeat() {
    console.log("This Heart has a beat");
    this.connected = true;
};

app.use(express.static('./Client'));

wss.on('connection', (ws, request) => {
    console.log(`New homie on board: ${request.session.username}`);
    clients.add(ws);

    ws.connected = true;
    ws.on('pong', () => { ws.connected = true; });
    ws.on('error', console.error);

    ws.on('message', (message) => {
        console.log(`${request.session.username}: ${message}`);

        // ✅ Broadcast messages with username
        for (const client of clients) {
            if (client.readyState === ws.OPEN) {
                client.send(`${request.session.username}: ${message}`);
            }
        }
    });

    ws.on('close', () => {
        console.log(`${request.session.username} disconnected`);
        clients.delete(ws);
        clearInterval(beat);
    });
});

const beat = setInterval(function ping() {
    wss.clients.forEach(function each(ws) {
        console.log("Heart is beating");
        if(ws.connected === false) {
            console.log("Heart is lost");
            return ws.terminate();
        }
        ws.connected = false;
        ws.ping();
    });
}, 30000);



httpsServer.listen(PORT, '0.0.0.0', () => {
    console.log('Secure WebSocket Server running on **********');
});

httpsServer.on('upgrade', function upgrade(request, socket, head) {
    const urlParams = new URLSearchParams(request.url.split('?')[1]);
    const token = urlParams.get('token');

    if (token !== 'mysecrettoken') {  
        console.log("Unauthorized WebSocket connection attempt");
        socket.destroy();
        return;
    }

    const cookies = parse(request.headers.cookie || '');
    const sessionID = cookies['connect.sid'];

    sessionMiddleware(request, {}, () => {
        if (!request.session.username) {
            console.log("Unauthorized WebSocket request - No username in session");
            socket.destroy();
            return;
        }

        wss.handleUpgrade(request, socket, head, function done(ws) {
            wss.emit('connection', ws, request);
        });
    });
});
