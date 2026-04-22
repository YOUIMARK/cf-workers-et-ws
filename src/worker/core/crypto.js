import crypto from 'crypto';
import { HEADER_SIZE } from './constants.js';
import { applyLatencyFirstFlag } from './packet.js';

const U64_MASK = (1n << 64n) - 1n;

function getRandomBytes(len) { return crypto.randomBytes(len); }

function rotl64(x, b) {
  return ((x << BigInt(b)) | (x >> (64n - BigInt(b)))) & U64_MASK;
}

function readUInt64LE(buf, offset) {
  let r = 0n;
  for (let i = 0; i < 8; i++) r |= BigInt(buf[offset + i]) << (8n * BigInt(i));
  return r;
}

function sipRound(v) {
  v.v0 = (v.v0 + v.v1) & U64_MASK; v.v1 = rotl64(v.v1, 13); v.v1 ^= v.v0; v.v0 = rotl64(v.v0, 32);
  v.v2 = (v.v2 + v.v3) & U64_MASK; v.v3 = rotl64(v.v3, 16); v.v3 ^= v.v2;
  v.v0 = (v.v0 + v.v3) & U64_MASK; v.v3 = rotl64(v.v3, 21); v.v3 ^= v.v0;
  v.v2 = (v.v2 + v.v1) & U64_MASK; v.v1 = rotl64(v.v1, 17); v.v1 ^= v.v2; v.v2 = rotl64(v.v2, 32);
}

function sipHash13(msg, k0 = 0n, k1 = 0n) {
  const b = BigInt(msg.length) << 56n;
  const v = {
    v0: 0x736f6d6570736575n ^ k0, v1: 0x646f72616e646f6dn ^ k1,
    v2: 0x6c7967656e657261n ^ k0, v3: 0x7465646279746573n ^ k1,
  };
  const fullLen = msg.length - (msg.length % 8);
  for (let i = 0; i < fullLen; i += 8) {
    const m = readUInt64LE(msg, i);
    v.v3 ^= m; sipRound(v); v.v0 ^= m;
  }
  let m = b;
  const left = msg.length % 8;
  for (let i = 0; i < left; i++) m |= BigInt(msg[fullLen + i]) << (8n * BigInt(i));
  v.v3 ^= m; sipRound(v); v.v0 ^= m;
  v.v2 ^= 0xffn;
  sipRound(v); sipRound(v); sipRound(v);
  return (v.v0 ^ v.v1 ^ v.v2 ^ v.v3) & U64_MASK;
}

class DefaultHasher {
  constructor() { this.parts = []; this.total = 0; }
  write(buf) {
    if (!buf || buf.length === 0) return;
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
    this.parts.push(b); this.total += b.length;
  }
  finish() {
    const msg = this.parts.length === 1 ? this.parts[0] : Buffer.concat(this.parts, this.total);
    return sipHash13(msg);
  }
}

function u64ToBeBytes(u64) {
  const out = Buffer.alloc(8);
  let x = u64;
  for (let i = 7; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

export function deriveKeys(networkSecret = '') {
  const secretBuf = Buffer.from(networkSecret, 'utf8');
  const h128 = new DefaultHasher();
  h128.write(secretBuf);
  const key128 = Buffer.alloc(16);
  u64ToBeBytes(h128.finish()).copy(key128, 0);
  h128.write(key128.subarray(0, 8));
  u64ToBeBytes(h128.finish()).copy(key128, 8);
  h128.write(key128);
  const h256 = new DefaultHasher();
  h256.write(secretBuf);
  h256.write(Buffer.from('easytier-256bit-key', 'utf8'));
  const key256 = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    if (i > 0) h256.write(key256.subarray(0, i * 8));
    h256.write(Buffer.from([i]));
    u64ToBeBytes(h256.finish()).copy(key256, i * 8, 0, 8);
  }
  return { key128, key256 };
}

export function generateDigestFromStr(str1, str2, digestLen = 32) {
  const len = Number(digestLen);
  if (!Number.isInteger(len) || len <= 0 || (len % 8) !== 0) throw new Error('digest length must be multiple of 8');
  const h = new DefaultHasher();
  h.write(Buffer.from(String(str1 || ''), 'utf8'));
  h.write(Buffer.from(String(str2 || ''), 'utf8'));
  const digest = Buffer.alloc(len);
  for (let i = 0; i < len / 8; i++) {
    u64ToBeBytes(h.finish()).copy(digest, i * 8);
    h.write(digest.subarray(0, (i + 1) * 8));
  }
  return digest;
}

export function encryptAesGcm(payload, key) {
  const nonce  = getRandomBytes(12);
  const algo   = key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
  const cipher = crypto.createCipheriv(algo, key, nonce);
  const ct     = Buffer.concat([cipher.update(payload), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag(), nonce]);
}

export function decryptAesGcm(payload, key) {
  if (payload.length < 28) throw new Error(`Encrypted payload too short: ${payload.length}`);
  const textLen  = payload.length - 28;
  const algo     = key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
  const decipher = crypto.createDecipheriv(algo, key, payload.subarray(textLen + 16));
  decipher.setAuthTag(payload.subarray(textLen, textLen + 16));
  return Buffer.concat([decipher.update(payload.subarray(0, textLen)), decipher.final()]);
}

export function randomU64String() {
  const b = getRandomBytes(8);
  let x = 0n;
  for (let i = 0; i < 8; i++) x = (x << 8n) | BigInt(b[i]);
  return x.toString();
}

export function sha256() { return crypto.createHash('sha256'); }

/**
 * wrapPacket — 封装数据包 (含可选加密)。
 *
 * 修复 1: 原版先调用 createHeader(flags=0), 再 writeUInt8(flags, 9) 覆盖,
 *         两步之间 createHeader 内部的 LATENCY_FIRST 位被清零。
 *         现在: 先将所有标志位 (加密 | LATENCY_FIRST) 合并到 flags,
 *         再统一传给 createHeader, 不再二次覆盖。
 *
 * 修复 2: LATENCY_FIRST 从 ws._env (CF env 绑定) 读取,
 *         解决 wrangler.toml [vars] 不注入 process.env 的问题。
 *
 * 优化: allocUnsafe + copy 替代 Buffer.concat, 减少热路径 GC 压力。
 */
export function wrapPacket(createHeaderFn, fromPeerId, toPeerId, packetType, payload, ws, opts = {}) {
  const encryptionEnabled = !!(ws && ws.crypto && ws.crypto.enabled);
  let body  = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let flags = 0;

  if (encryptionEnabled && !opts.disableEncrypt && packetType !== 2) {
    const algo = (ws.crypto && ws.crypto.algorithm) || 'aes-gcm';
    if      (algo === 'aes-gcm')     body = encryptAesGcm(body, ws.crypto.key128);
    else if (algo === 'aes-256-gcm') body = encryptAesGcm(body, ws.crypto.key256);
    else throw new Error(`Unsupported encryption algorithm: ${algo}`);
    flags |= 0x01;
  }

  // LATENCY_FIRST 从 ws._env 读取 (CF env 绑定), 不读 process.env
  flags = applyLatencyFirstFlag(flags, ws && ws._env);

  const headerBuf = createHeaderFn(fromPeerId, toPeerId, packetType, body.length, flags);
  const out = Buffer.allocUnsafe(HEADER_SIZE + body.length);
  headerBuf.copy(out, 0);
  body.copy(out, HEADER_SIZE);
  return out;
}
