import { createServer } from 'https';
import { WebSocketServer } from 'ws';

function onSocketError(err) {
    console.error(err);
}

const server = createServer();
const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', function connection(ws, request, client) {
    ws.on('error', console.error);

    ws.on('message', function message(data) {
        console.log(`Recieved message ${data} from user ${client}`);
        ws.send(`Recieved message ${data} from user ${client}`);
    });

    
});

server.on('upgrade', function upgrade(request, socket, head) {
    socket.on('error', onSocketError);

    AuthenticatorResponse(request, function next(err, client) {
        if (err || !client) {
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destory();
            return;
        }

        socket.removeListener('error', onSocketError);

        wss.handleUpgrade(request, socket, head, function done(ws) {
            wss.emit('connection', ws, request, client);
        });
    });
});
