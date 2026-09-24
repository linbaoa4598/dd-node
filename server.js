// VMess over WebSocket 节点，用 Node.js 实现，用来替代需要 Docker 的 Xray。
// 只实现 FlClash 实际用到的子集：AES-128-GCM、无 alterId、WebSocket 传输、TCP 转发。
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const UUID = process.env.UUID || 'e7686976-f387-4674-a459-4b543d433688';
const WS_PATH = process.env.WS_PATH || '/c214cf6df5df';

const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');
// 命令密钥：MD5(UUID)，用来校验连接身份和派生头部密钥。
const cmdKey = crypto.createHash('md5').update(uuidBytes).digest();

// 嵌套 HMAC-SHA256，和 v2ray 的 KDF 一致。最内层密钥是固定字符串，
// 每一层的密钥是上一层对当前路径字符串求 HMAC 的结果，最后写入原始密钥。
function kdf(key, path) {
  let hmacKey = Buffer.from('VMess AEAD KDF');
  for (const p of path) hmacKey = crypto.createHmac('sha256', hmacKey).update(p).digest();
  return crypto.createHmac('sha256', hmacKey).update(key).digest();
}

// 每个连接从请求体派生独立的密钥和 IV，响应方向再派生一次。
function derive(body) {
  const key = crypto.createHash('md5').update(uuidBytes).update(body).digest();
  const iv = crypto.createHash('md5').update(body).update(uuidBytes).digest();
  return {
    key, iv,
    respKey: crypto.createHash('md5').update(key).digest(),
    respIv: crypto.createHash('md5').update(iv).digest(),
  };
}

// AES-128-GCM，密文末尾是 16 字节校验值。
function gcmDecrypt(key, iv, data, aad) {
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(data.subarray(data.length - 16));
  if (aad) decipher.setAAD(aad);
  return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
}
function gcmEncrypt(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
}

// 每个数据块的 nonce：以 IV 为基数，前两字节放递增的块序号。
function chunkNonce(iv, count) {
  const n = Buffer.from(iv);
  n.writeUInt16BE(count, 0);
  return n.subarray(0, 12);
}

// 把收到的字节流切成数据块并解密。
// 每块先是 2 字节长度（用 auth_len 密钥加密），再是对应长度的内容（用数据密钥加密）。
function makeStreamDecoder(session, onData) {
  let buf = Buffer.alloc(0);
  let expect = null;
  let count = 0;
  const lenKey = kdf(session.key, ['auth_len']).subarray(0, 16);
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (expect === null) {
        if (buf.length < 18) return;
        const len = gcmDecrypt(lenKey, chunkNonce(session.iv, count), buf.subarray(0, 18));
        expect = len.readUInt16BE(0);
        buf = buf.subarray(18);
      }
      if (buf.length < expect + 16) return;
      onData(gcmDecrypt(session.key, chunkNonce(session.iv, count), buf.subarray(0, expect + 16)));
      buf = buf.subarray(expect + 16);
      expect = null;
      count++;
    }
  };
}

// 把要发出的数据切成加密块。
function encodeChunk(session, data, count) {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(data.length);
  const lenKey = kdf(session.respKey, ['auth_len']).subarray(0, 16);
  return Buffer.concat([
    gcmEncrypt(lenKey, chunkNonce(session.respIv, count), len),
    gcmEncrypt(session.respKey, chunkNonce(session.respIv, count), data),
  ]);
}

// 解密 VMess 的 AEAD 请求头。
// 布局：16 字节 authid、18 字节加密长度、8 字节随机数、加密的头部。
// 密钥由命令密钥、authid 和随机数经 KDF 派生。返回头部明文和总消耗字节数。
function openHeader(buf) {
  if (buf.length < 16 + 18 + 8) return null;
  const authid = buf.subarray(0, 16);
  // 校验 authid：解密后前 12 字节的 CRC32 必须等于后 4 字节，且时间差在两分钟内。
  const authKey = kdf(cmdKey, ['AES Auth ID Encryption']).subarray(0, 16);
  const dec = crypto.createDecipheriv('aes-128-ecb', authKey, null);
  dec.setAutoPadding(false);
  const plain = Buffer.concat([dec.update(authid), dec.final()]);
  const ts = Number(plain.readBigInt64BE(0));
  if (plain.readUInt32BE(12) !== crc32(plain.subarray(0, 12))) return null;
  if (Math.abs(ts - Date.now() / 1000) > 120) return null;

  const nonce = buf.subarray(34, 42);
  const lenKey = kdf(cmdKey, ['VMess Header AEAD Key_Length', authid, nonce]).subarray(0, 16);
  const lenNonce = kdf(cmdKey, ['VMess Header AEAD Nonce_Length', authid, nonce]).subarray(0, 12);
  const lenPlain = gcmDecrypt(lenKey, lenNonce, buf.subarray(16, 34), authid);
  const length = lenPlain.readUInt16BE(0);

  if (buf.length < 42 + length + 16) return null;
  const hdrKey = kdf(cmdKey, ['VMess Header AEAD Key', authid, nonce]).subarray(0, 16);
  const hdrNonce = kdf(cmdKey, ['VMess Header AEAD Nonce', authid, nonce]).subarray(0, 12);
  const header = gcmDecrypt(hdrKey, hdrNonce, buf.subarray(42, 42 + length + 16), authid);
  return { header, consumed: 42 + length + 16 };
}

function crc32(buf) {
  let c = ~0;
  for (const b of buf) {
    c ^= b;
    for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function parseHeader(buf) {
  let o = 0;
  o++;                                        // 版本
  o += 16;                                    // IV
  o += 16;                                    // key
  const v = buf[o++];                         // 响应认证字节
  const opt = buf[o++];
  const pad = opt >> 4;
  const sec = opt & 0xf;
  o++;                                        // 保留
  const cmd = buf[o++];
  const port = buf.readUInt16BE(o); o += 2;
  const atyp = buf[o++];
  let host;
  if (atyp === 1) { host = [...buf.subarray(o, o + 4)].join('.'); o += 4; }
  else if (atyp === 2) { const n = buf[o++]; host = buf.subarray(o, o + n).toString(); o += n; }
  else if (atyp === 3) { host = buf.subarray(o, o + 16).toString('hex').replace(/(.{4})/g, '$1:').slice(0, -1); o += 16; }
  else return null;
  o += pad;
  o++;                                        // 校验字节
  return { v, sec, cmd, host, port, rest: buf.subarray(o) };
}

const server = http.createServer((req, res) => {
  // 普通 HTTP 请求返回一个页面，看起来像正常网站。
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end('<!doctype html><meta charset="utf-8"><title>welcome</title><p>ok</p>');
});

const wss = new WebSocketServer({ server, path: WS_PATH });

wss.on('connection', (ws) => {
  let session = null;
  let upstream = null;
  let decode = null;
  const headerBuf = [];

  const send = (data) => { if (ws.readyState === ws.OPEN) ws.send(data); };
  let respCount = 0;

  const start = (header) => {
    if (header.cmd !== 1 || header.sec !== 3) { ws.close(); return; }
    upstream = net.connect(header.port, header.host);
    upstream.on('connect', () => {
      // 先回一个认证字节，告诉客户端握手成功。
      send(gcmEncrypt(session.respKey, session.respIv, Buffer.from([header.v])));
      if (header.rest.length) upstream.write(header.rest);
    });
    upstream.on('data', (data) => send(encodeChunk(session, data, respCount++)));
    upstream.on('error', () => ws.close());
    upstream.on('close', () => ws.close());
  };

  ws.on('message', (data) => {
    try {
      if (!session) {
        // 第一个消息携带请求头：authid、加密长度、随机数、加密头部，后面紧跟数据块。
        const raw = Buffer.from(data);
        const opened = openHeader(raw);
        if (!opened) { ws.close(); return; }
        const header = parseHeader(opened.header);
        if (!header) { ws.close(); return; }
        session = derive(opened.header.subarray(0, 16));
        decode = makeStreamDecoder(session, (payload) => {
          if (upstream && upstream.writable) upstream.write(payload);
        });
        start(header);
        if (raw.length > opened.consumed) decode(raw.subarray(opened.consumed));
        return;
      }
      const result = decode(Buffer.from(data));
      if (result === 'end') ws.close();
    } catch {
      ws.close();
    }
  });
  ws.on('close', () => upstream && upstream.destroy());
  ws.on('error', () => upstream && upstream.destroy());
});

server.listen(PORT, () => console.log(`vmess-ws listening on ${PORT}, path ${WS_PATH}`));
