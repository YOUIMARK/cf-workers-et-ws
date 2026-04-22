import { Buffer } from 'buffer';
import { HEADER_SIZE } from './constants.js';

export function parseHeader(buffer) {
  if (!buffer || buffer.length < HEADER_SIZE) return null;
  return {
    fromPeerId:     buffer.readUInt32LE(0),
    toPeerId:       buffer.readUInt32LE(4),
    packetType:     buffer.readUInt8(8),
    flags:          buffer.readUInt8(9),
    forwardCounter: buffer.readUInt8(10),
    reserved:       buffer.readUInt8(11),
    len:            buffer.readUInt32LE(12),
  };
}

/**
 * createHeader — 构造 16 字节包头。
 *
 * 修复: 原版在此处读取 process.env.EASYTIER_LATENCY_FIRST 并写入 flags,
 *       但 wrapPacket 之后再次 writeUInt8(flags, 9) 将其覆盖,
 *       且 CF Workers [vars] 不注入 process.env, 导致双重失效。
 * 现在 createHeader 只写入调用方传入的 flags, 不读取任何环境变量。
 * LATENCY_FIRST 标志由 wrapPacket 通过 applyLatencyFirstFlag 在合并后统一注入。
 */
export function createHeader(fromPeerId, toPeerId, packetType, payloadLen, flags = 0, forwardCounter = 1) {
  const buf = Buffer.alloc(HEADER_SIZE);
  buf.writeUInt32LE(fromPeerId,    0);
  buf.writeUInt32LE(toPeerId,      4);
  buf.writeUInt8(packetType,       8);
  buf.writeUInt8(flags,            9);
  buf.writeUInt8(forwardCounter,  10);
  buf.writeUInt8(0,               11);
  buf.writeUInt32LE(payloadLen,   12);
  return buf;
}

/**
 * applyLatencyFirstFlag — 将 LATENCY_FIRST 位 (0x02) 合并到 flags。
 * 从 CF env 绑定 (ws._env) 读取, 而非 process.env。
 */
export function applyLatencyFirstFlag(flags, env) {
  return (env && env.EASYTIER_LATENCY_FIRST === '1') ? (flags | 0x02) : flags;
}
