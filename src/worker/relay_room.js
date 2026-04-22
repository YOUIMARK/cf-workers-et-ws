/**
 * EasyTier WebSocket 中继房间 (Durable Object)
 *
 * 修复列表:
 * [wsPath]    fetch(): 修复 '/' + env.WS_PATH || '/ws' 运算符优先级错误。
 * [setEnv]    构造函数调用 peerManager.setEnv(env), 注入 CF env 绑定。
 * [Hibernate] 批量恢复期间设 _inHibernationRestore, 恢复后统一 bump 一次版本号。
 * [ws._env]   _initSocket 将 CF env 存入 ws._env, 供下游读取配置。
 * [M1]        _cleanup: removeNetworkGroupActivity 提前到 peerId 守卫之前。
 * [M3]        _sendPing: 握手未完成 (!ws.peerId) 时跳过, 避免向 toPeerId=0 发噪音包。
 * [HB-env]    _startHeartbeat: 从 env 读取心跳间隔和超时, 原版硬编码忽略 wrangler.toml 配置。
 */

import { Buffer } from 'buffer';
import { parseHeader, createHeader } from './core/packet.js';
import { PacketType, HEADER_SIZE, MY_PEER_ID } from './core/constants.js';
import { loadProtos } from './core/protos.js';
import {
  handleHandshake, handlePing, handleForwarding,
  updateNetworkGroupActivity, removeNetworkGroupActivity
} from './core/basic_handlers.js';
import { handleRpcReq, handleRpcResp } from './core/rpc_handler.js';
import { getPeerManager } from './core/peer_manager.js';
import { randomU64String } from './core/crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

export class RelayRoom {
  constructor(state, env) {
    this.state       = state;
    this.env         = env;
    this.types       = loadProtos();
    this.peerManager = getPeerManager();
    this.peerManager.setTypes(this.types);

    // [setEnv] CF env 绑定注入 PeerManager
    this.peerManager.setEnv(env);

    // [Hibernate] 批量恢复: 恢复期间跳过逐 peer bump, 恢复后按 group 统一 bump 一次
    this.peerManager._inHibernationRestore = true;
    const restoredGroups = new Set();
    this.state.getWebSockets().forEach(ws => {
      this._restoreSocket(ws);
      if (ws.groupKey) restoredGroups.add(String(ws.groupKey));
    });
    this.peerManager._inHibernationRestore = false;
    for (const gk of restoredGroups) this.peerManager.bumpAllPeerConnVersions(gk);
  }

  async fetch(request) {
    const url = new URL(request.url);
    // [wsPath] 修复运算符优先级错误
    const wsPath = this.env.WS_PATH ? `/${this.env.WS_PATH}` : '/ws';
    if (url.pathname !== wsPath) return new Response('Not found', { status: 404 });
    if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected websocket', { status: 400 });

    const pair = new WebSocketPair();
    this.state.acceptWebSocket(pair[1]);
    this._initSocket(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(ws, message) {
    try {
      let buffer;
      if      (message instanceof ArrayBuffer)                       buffer = Buffer.from(message);
      else if (message instanceof Uint8Array)                        buffer = Buffer.from(message);
      else if (ArrayBuffer.isView(message) && message.buffer)        buffer = Buffer.from(message.buffer);
      else if (typeof message === 'string') {
        // EasyTier 协议仅使用二进制帧; 文本帧表示客户端配置有误
        console.warn(`[ws] TEXT frame from peer ${ws.peerId} — EasyTier uses binary frames only`);
        return;
      } else {
        console.warn(`[ws] Unsupported message type: ${typeof message} from peer ${ws.peerId}`);
        return;
      }

      ws.lastSeen = Date.now();
      const header = parseHeader(buffer);
      if (!header) { console.error('[ws] parseHeader failed'); return; }
      const payload = buffer.subarray(HEADER_SIZE);

      switch (header.packetType) {
        case PacketType.HandShake:
          handleHandshake(ws, header, payload, this.types);
          break;
        case PacketType.Ping:
          handlePing(ws, header, payload);
          break;
        case PacketType.Pong:
          this._handlePong(ws);
          break;
        case PacketType.RpcReq:
          if (header.toPeerId === undefined || header.toPeerId === null || header.toPeerId === MY_PEER_ID) {
            handleRpcReq(ws, header, payload, this.types);
          } else {
            handleForwarding(ws, header, buffer, this.types);
          }
          break;
        case PacketType.RpcResp:
          if (header.toPeerId === undefined || header.toPeerId === null || header.toPeerId === MY_PEER_ID) {
            handleRpcResp(ws, header, payload, this.types);
          } else {
            handleForwarding(ws, header, buffer, this.types);
          }
          break;
        case PacketType.Data:
        default:
          handleForwarding(ws, header, buffer, this.types);
      }
    } catch (e) {
      console.error('[RelayRoom] Message handling error:', e);
    }
  }

  async webSocketClose(ws) { this._cleanup(ws); }
  async webSocketError(ws)  { this._cleanup(ws); }

  /**
   * _cleanup — 统一断线清理 (含防抖锁)。
   *
   * [M1] removeNetworkGroupActivity 提前到 peerId 守卫之前:
   *      握手已完成 (groupKey 已设) 但断线时, 不论 peerId 是否存在都需要恢复 peerCount。
   *      (注: 实际上 groupKey 和 peerId 总是同时设置, 此修复属防御性设计。)
   */
  _cleanup(ws) {
    if (ws.isCleanedUp) return;
    ws.isCleanedUp = true;

    if (ws.heartbeatInterval) {
      clearInterval(ws.heartbeatInterval);
      ws.heartbeatInterval = null;
    }

    // [M1] 提前执行, 不依赖 peerId
    if (ws.groupKey) {
      try { removeNetworkGroupActivity(ws.groupKey); }
      catch (e) { console.error('[Cleanup] removeNetworkGroupActivity error:', e); }
    }

    if (!ws.peerId) return;

    const groupKey = ws.groupKey;
    const removed  = this.peerManager.removePeer(ws);
    if (removed) {
      try { this.peerManager.broadcastRouteUpdate(this.types, groupKey, null, { forceFull: true }); }
      catch (_) {}
    }
  }

  _initSocket(ws, meta = {}) {
    ws.peerId           = meta.peerId          || null;
    ws.groupKey         = meta.groupKey        || null;
    ws.domainName       = meta.domainName      || null;
    ws.lastSeen         = Date.now();
    ws.lastPingSent     = 0;
    ws.lastPongReceived = Date.now(); // 初始化为当前时间, 避免 0 值导致立即超时
    ws.serverSessionId  = meta.serverSessionId || randomU64String();
    ws.weAreInitiator   = false;
    ws.crypto           = { enabled: false };
    ws.heartbeatInterval = null;
    ws.isCleanedUp      = false;

    // [ws._env] CF env 绑定, 供 basic_handlers / crypto / rpc_handler 读取配置
    ws._env = this.env;

    ws.serializeAttachment?.({
      peerId:          ws.peerId,
      groupKey:        ws.groupKey,
      domainName:      ws.domainName,
      serverSessionId: ws.serverSessionId,
    });

    this._startHeartbeat(ws);
  }

  _restoreSocket(ws) {
    const meta = ws.deserializeAttachment ? (ws.deserializeAttachment() || {}) : {};
    this._initSocket(ws, meta);
    if (ws.peerId && ws.groupKey) this.peerManager.addPeer(ws.peerId, ws);
  }

  /**
   * [HB-env] 从 CF env 读取心跳参数。
   * 原版硬编码 10000/25000ms, 即使 wrangler.toml 配置了对应变量也无效。
   */
  _startHeartbeat(ws) {
    if (ws.heartbeatInterval) clearInterval(ws.heartbeatInterval);
    const env               = this.env || {};
    const heartbeatInterval = Number(env.EASYTIER_HEARTBEAT_INTERVAL || 10_000);
    const connectionTimeout = Number(env.EASYTIER_CONNECTION_TIMEOUT  || 25_000);
    const checkInterval     = Math.min(5_000, Math.floor(heartbeatInterval / 2));

    ws.heartbeatInterval = setInterval(() => {
      try {
        if (ws.readyState === WS_OPEN) {
          const now = Date.now();
          if (now - ws.lastPingSent > heartbeatInterval) {
            this._sendPing(ws);
            ws.lastPingSent = now;
          }
          if (now - ws.lastPongReceived > connectionTimeout) {
            console.log(`[Heartbeat] Timeout for peer ${ws.peerId}, forcing cleanup`);
            this._cleanup(ws);
            try { ws.close(); } catch (_) {}
          }
        } else {
          this._cleanup(ws);
        }
      } catch (e) { console.error('[Heartbeat] Error:', e); }
    }, checkInterval);
  }

  /**
   * [M3] 握手未完成 (!ws.peerId) 时跳过, 避免向 toPeerId=0/null 发噪音包。
   */
  _sendPing(ws) {
    try {
      if (ws.readyState !== WS_OPEN) return;
      if (!ws.peerId) return; // [M3]
      const pingData = Buffer.from('ping');
      const header   = createHeader(MY_PEER_ID, ws.peerId, PacketType.Ping, pingData.length);
      ws.send(Buffer.concat([header, pingData]));
    } catch (e) { console.error(`[Heartbeat] Ping failed to peer ${ws.peerId}:`, e); }
  }

  _handlePong(ws) { ws.lastPongReceived = Date.now(); }
}
