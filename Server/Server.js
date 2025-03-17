import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bodyParser from 'body-parser';
import hashFun from './src/hash.js';
import express from 'express';
import https from 'https';
import path from 'path';
import fs from 'fs';
import updateLog from './src/chatLog.js';

const app = express();
const PORT = process.env.PORT || 8080;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const options = {
    key: fs.readFileSync('./certs/key.pem'),
    cert: fs.readFileSync('./certs/cert.pem')
};
const sessionMiddleware = session({
    secret: 'mySecretKey', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
});
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many messages, You are on timeout'
});

const httpsServer = https.createServer(options, app);
const wss = new WebSocketServer({ noServer: true});
const clients = new Set();

function onSocketError(err) {
    console.error(err);
};

const beat = setInterval(function ping() {
    wss.clients.forEach(function each(ws) {
        console.log(`Heart is still beating`);
        if(ws.connected === false) {
            console.log(`Heart has stopped beating`);
            return ws.terminate();
        }
        ws.connected = false;
        ws.ping();
    });
}, 30000);

app.use(sessionMiddleware);
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './client')));
app.use(express.static('./client'));
app.use(limiter);

app.post('/index', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Missing username or password" });
    }
    else {
        // Runs the imported hashing function for salting and hashing
        const hashName = hashFun(username, false);
        const hashPass = hashFun(password, true);
        
        //If check to see if information passes in database otherwise, return the failure
        // if(!true) {
        //     return res.json({ success: false, message: "Username or Password incorrect" });
        // }
        console.log(`Returning Username Hash: ${hashName}`);
        console.log(`Returning Password Hash: ${hashPass}`);
    }
    req.session.username = username;
    res.json({ success: true });
});

app.get('/chat', (req, res) => {
    if (!req.session.username) {
        return res.status(403).send("Access Denied. Please login.");
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

wss.on('connection', (ws, request) => {
    console.log(`New homie on board: ${request.session.username}`);
    clients.add(ws);
    ws.connected = true;
    
    const used = process.memoryUsage().heapUsed / 1024 / 1024;
    for (const client of clients) {
        if (client.readyState === ws.OPEN) {
            const allFileContents = fs.readFileSync('./chatlogs/chatlog.txt', 'utf-8');
            allFileContents.split(/\r?\n/).forEach(line => {
                client.send(line);
            });
            console.log("Pulled Chat Log"); 
        };
    };

    ws.on('pong', () => { ws.connected = true; });
    ws.on('error', console.error);
    ws.on('message', (message) => {
        console.log(`${request.session.username}: ${message}`);

        for (const client of clients) {
            if (client.readyState === ws.OPEN) {
                client.send(`${request.session.username}: ${message}`);
                const compiledMess = `${request.session.username}: ${message}`;
                console.log("Saving Compiled Message");
                const chatlogFile = './chatlogs/chatlog.txt';
                updateLog(compiledMess, chatlogFile);
                console.log("Updated Text File"); 
            }
        }
    });
    // Need to implement this completely and look into FTP for the file transfer process
    ws.on('sendFile', (fileInput) => {
        console.log("Sending Files");
        console.log(fileInput);
    });
    ws.on('close', () => {
        console.log(`${request.session.username} disconnected`);
        clients.delete(ws);
        clearInterval(beat);
    });
});

httpsServer.on('upgrade', function upgrade(request, socket, head) {
    const urlParams = new URLSearchParams(request.url.split('?')[1]);
    const token = urlParams.get('token');

    if (token !== 'mysecrettoken') {  
        console.log("Unauthorized WebSocket connection attempt");
        socket.destroy();
        return;
    };

    sessionMiddleware(request, {}, () => {
        if (!request.session.username) {
            console.log("Unauthorized WebSocket request - No username in session");
            socket.destroy();
            return;
        };
        wss.handleUpgrade(request, socket, head, function done(ws) {
            wss.emit('connection', ws, request);
        });
    });
});

httpsServer.listen(PORT, '0.0.0.0', () => {
    console.log('Secure WebSocket Server running on **********');
});