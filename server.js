import net from "node:net";
import { createHash, timingSafeEqual } from "node:crypto";

const SOCKS_PORT = Number(process.env.SOCKS_PORT) || 1080;
const SOCKS_USER = process.env.SOCKS_USER || "";
const SOCKS_PASS = process.env.SOCKS_PASS || "";
const AUTH_REQUIRED = Boolean(SOCKS_USER && SOCKS_PASS);

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest();
}

function safeEqual(a, b) {
  return timingSafeEqual(sha256(a), sha256(b));
}

function readExactly(socket, n, carry) {
  return new Promise((resolve, reject) => {
    let buf = carry || Buffer.alloc(0);
    if (buf.length >= n) {
      resolve({ data: buf.subarray(0, n), rest: buf.subarray(n) });
      return;
    }
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= n) {
        cleanup();
        resolve({ data: buf.subarray(0, n), rest: buf.subarray(n) });
      }
    };
    const onClose = () => {
      cleanup();
      reject(new Error("client closed"));
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    function cleanup() {
      socket.off("data", onData);
      socket.off("close", onClose);
      socket.off("error", onError);
    }
    socket.on("data", onData);
    socket.on("close", onClose);
    socket.on("error", onError);
  });
}

async function handleConnection(client) {
  client.on("error", () => {});
  try {
    let step = await readExactly(client, 2);
    const nmethods = step.data[1];
    step = await readExactly(client, nmethods, step.rest);
    const methods = Array.from(step.data);

    if (AUTH_REQUIRED) {
      if (!methods.includes(2)) {
        client.end(Buffer.from([5, 0xff]));
        return;
      }
      client.write(Buffer.from([5, 2]));

      step = await readExactly(client, 2, step.rest);
      const ulen = step.data[1];
      step = await readExactly(client, ulen, step.rest);
      const uname = step.data.toString("utf8");
      step = await readExactly(client, 1, step.rest);
      const plen = step.data[0];
      step = await readExactly(client, plen, step.rest);
      const passwd = step.data.toString("utf8");

      const ok = safeEqual(uname, SOCKS_USER) && safeEqual(passwd, SOCKS_PASS);
      client.write(Buffer.from([1, ok ? 0 : 1]));
      if (!ok) {
        client.destroy();
        return;
      }
    } else {
      if (!methods.includes(0)) {
        client.end(Buffer.from([5, 0xff]));
        return;
      }
      client.write(Buffer.from([5, 0]));
    }

    step = await readExactly(client, 4, step.rest);
    const cmd = step.data[1];
    const atyp = step.data[3];
    if (cmd !== 1) {
      client.end(Buffer.from([5, 7, 0, 1, 0, 0, 0, 0, 0, 0]));
      return;
    }

    let host;
    if (atyp === 1) {
      step = await readExactly(client, 4, step.rest);
      host = Array.from(step.data).join(".");
    } else if (atyp === 4) {
      step = await readExactly(client, 16, step.rest);
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        parts.push(step.data.readUInt16BE(i).toString(16));
      }
      host = parts.join(":");
    } else if (atyp === 3) {
      step = await readExactly(client, 1, step.rest);
      const len = step.data[0];
      step = await readExactly(client, len, step.rest);
      host = step.data.toString("utf8");
    } else {
      client.end(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
      return;
    }

    step = await readExactly(client, 2, step.rest);
    const port = step.data.readUInt16BE(0);
    const leftover = step.rest;

    const upstream = net.connect({ host, port }, () => {
      client.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      if (leftover.length) upstream.write(leftover);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
    upstream.on("close", () => client.destroy());
  } catch {
    client.destroy();
  }
}

const server = net.createServer(handleConnection);
server.listen(SOCKS_PORT, () => {
  if (!AUTH_REQUIRED) {
    console.log("warning: SOCKS_USER/SOCKS_PASS not set, relay is running without authentication");
  }
  console.log(`socks5 relay listening on ${SOCKS_PORT}`);
});
