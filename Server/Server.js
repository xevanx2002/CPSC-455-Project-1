import { WebSocketServer } from 'ws';
import express from 'express';

const app = express();
const PORT = process.env.PORT || 8080;
const httpServer = app.listen(PORT);
const wss = new WebSocketServer({ noServer: true });

function onSocketError(err) {
    console.error(err);
};

function heartBeat() {
    console.log("This Heart has a beat");
    this.connected = true;
};

app.use(express.static('../Client'));

wss.on('connection', function connection(ws, request) {
    const id = "2236";

    console.log(`Session ID has been assigned: ${id}`)

    console.log(`Connection Established with user ${id}`);

    ws.send(`${id} has connected`);

    wss.connected = true;
    ws.on('pong', heartBeat);

    ws.on('error', console.error);

    ws.on('message', function message(data) {
        console.log(`${id}: ${data}`);
        ws.send(`${id}: ${data}`);
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
    console.log(`User ${request.session.userId} has disconnected`);
    clearInterval(beat);
});

httpServer.on('upgrade', function upgrade(request, socket, head) {
    socket.on('error', onSocketError);

    socket.removeListener('error', onSocketError);

    wss.handleUpgrade(request, socket, head, function done(ws) {
        wss.emit('connection', ws, request);
    });
});