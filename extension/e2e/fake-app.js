// Stand-in for the menu bar app: answers fill requests over the bridge socket.
"use strict";
const net = require("node:net");

function frame(obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const len = Buffer.alloc(4); len.writeUInt32LE(body.length);
  return Buffer.concat([len, body]);
}

function startFakeApp(path, answer) {
  const seen = [];
  const server = net.createServer(sock => {
    let buf = Buffer.alloc(0);
    sock.on("data", d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32LE(0)) {
        const n = buf.readUInt32LE(0);
        const msg = JSON.parse(buf.subarray(4, 4 + n).toString());
        buf = buf.subarray(4 + n);
        seen.push(msg);
        const reply = answer(msg);
        if (reply) sock.write(frame(reply));
      }
    });
  });
  return new Promise(r => server.listen(path, () => r({ server, seen })));
}

module.exports = { startFakeApp };
