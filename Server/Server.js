import { WebSocketServer } from 'ws';
import express from 'express';


const app = express();
const PORT = process.env.PORT || 8080;
const httpServer = app.listen(PORT, '0.0.0.0',() => {
    console.log('yuh baby girl les gooooo');
});
const wss = new WebSocketServer({ noServer: true });

const clients = new Set();

function onSocketError(err) {
    console.error(err);
};

function heartBeat() {
    console.log("This Heart has a beat");
    this.connected = true;
};

app.use(express.static('./Client'));

wss.on('connection', function connection(ws, request) {
    console.log("New homie on board");
    clients.add(ws);

    // console.log(`Session ID has been assigned: ${id}`)

    console.log(`Connection Established with user `);

    // ws.send(`${id} has connected`);

    ws.connected = true;
    ws.on('pong', heartBeat);

    ws.on('error', console.error);

    ws.on('message', (message) => {
        console.log(`Received: ${message}`);

        for (const client of clients) {
            if (client !== ws && client.readyState === ws.OPEN) {
                client.send(`${message}`);
                ws.send(`${message}`);
            }
        }
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

wss.on('close', function close () {
    console.log(`User has disconnected`);
    clients.delete(ws);
    clearInterval(beat);
});

httpServer.on('upgrade', function upgrade(request, socket, head) {
    socket.on('error', onSocketError);

    // socket.removeListener('error', onSocketError);

    wss.handleUpgrade(request, socket, head, function done(ws) {
        wss.emit('connection', ws, request);
    });
});