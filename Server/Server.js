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
const uploadDir = path.join(__dirname, 'uploads');
const IPAddress = 'https://127.0.0.1:8080/';

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
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
};

const httpsServer = https.createServer(options, app);
const wss = new WebSocketServer({ noServer: true});
const clients = new Set();
let dataMap = new Map();

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
app.use('/uploads', express.static(uploadDir));
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
                client.send(JSON.stringify({
                    type: 'logs',
                    text: line
                }));
            });
            console.log("Pulled Chat Log"); 
        };
    };

    ws.on('pong', () => { ws.connected = true; });
    ws.on('error', console.error);
    ws.on('message', (newData) => {
        console.log("This is Working");       

        const str = newData.toString('utf8');

        // Checking to see if recieved data is a json object before processing information
        let jsonCheck = false;
        try {
            const parsed = JSON.parse(str);
            jsonCheck = true;
            // If the returned data type is st to file, prepare the metadata to be captured
            if (parsed.type === 'file') {
                dataMap.set(ws, parsed);
            };
        } catch (err) {
            
            console.log("Is an object");
        };
        console.log(jsonCheck);
        
        if(!jsonCheck && Buffer.isBuffer(newData)) {
            console.log("File stuff happening");
            const metadata = dataMap.get(ws);
            if (!metadata) {
                console.log("No metadata");
                return;
            };
            
            console.log("Metadata recieved");
            const filePath = path.join(__dirname, 'uploads', `${metadata.fileName}`);

            fs.writeFileSync(filePath, newData);
            console.log(`File Recieved and Saved: ${filePath}`);
            // The complete URL to download the uploaded files from the server
            const fileURL = `${IPAddress}uploads/${metadata.fileName}`;
            const fileData = {
                type: 'file',
                fileName: metadata.fileName,
                sender: request.session.username,
                url: fileURL,
                date: metadata.date
            };

            for (const client of clients) {
                if(client.readyState === ws.OPEN) {
                    ws.send(JSON.stringify(fileData));
                    console.log("Sharing File");
                    const compiledMess = `(${fileData.date}) ${request.session.username}:  <a href="${fileURL}" downloads="${fileData.fileName}" targets="_blank">${fileData.fileName}</a>`;
                    const chatlogFile = './chatlogs/chatlog.txt';
                    // Adds the necessary files to the chatLog so a history is kept of the information
                    updateLog(compiledMess, chatlogFile);
                }
            };
            dataMap.delete(ws);
        }
        else {
            try {
                const sentData = JSON.parse(newData);
                console.log("Message stuff happening");

                if (sentData.type === 'message') {
                    console.log(`Time:${sentData.date} User:${request.session.username}: ${sentData.data}`);

                    for (const client of clients) {
                        if (client.readyState === ws.OPEN) {
                            client.send(JSON.stringify({
                                type: 'message',
                                sender: request.session.username,
                                date: sentData.date,
                                data: sentData.data
                            }));
                            console.log(sentData.data);
                            const compiledMess = `(${sentData.date}) ${request.session.username}:  ${sentData.data}`;
                            const chatlogFile = './chatlogs/chatlog.txt';
                            updateLog(compiledMess, chatlogFile);
                            console.log("Updated Text File"); 
                        }
                    }
                }
                else if (sentData.type === 'file') {
                    dataMap.set(ws, sentData);
                };
            } catch (err) {
                console.log("JSON type error");
            }
        }
        
    });
    ws.on('send_file', async (data, cb) => {
        if (data.type == 'file') {
            console.log("Binary recieved");
            cb("File recieved successfully");
        }
        ws.send(data);
    })
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