/**
 * EasyTier Peer 管理器
 *
 * 修复列表:
 * [CF-env]  构造函数不再读 process.env; 新增 setEnv(env) 由 RelayRoom 注入 CF env 绑定。
 * [H2]      addPeer / removePeer: groupKey 为空时提前返回, 不污染空 key 桶。
 * [Ghost-1] addPeer: 发现旧 WS 时设 oldWs.isCleanedUp=true, 抑制旧 close 事件。
 * [Ghost-2] removePeer: 身份校验 peers.get(peerId) !== ws 时返回 false, 防止误删新连接。
 * [Return]  removePeer: 实际删除时才返回 true (原版始终返回 true, 导致不必要的广播)。
 * [Bump]    _inHibernationRestore 标志: DO 批量恢复期间跳过逐 peer bump, 恢复后统一 bump。
 * [Default] broadcastRouteUpdate: 默认 forceFull=false, 避免无参调用触发全量广播风暴。
 * [Version] globalNetworkVersion 在构造函数中初始化, 不再惰性初始化。
 */

import { Buffer } from 'buffer';
import { MY_PEER_ID, PacketType, WS_OPEN } from './constants.js';
import { createHeader } from './packet.js';
import { wrapPacket, randomU64String } from './crypto.js';
import { getPeerCenterState, cleanPeerAndSubPeers } from './global_state.js';

// ── 工具函数 ──────────────────────────────────────────────────────────────────

function parseIpv4ToU32Be(ip) {
  const p = String(ip).trim().split('.').map(Number);
  if (p.length !== 4 || p.some(x => !Number.isInteger(x) || x < 0 || x > 255))
    throw new Error(`Invalid IPv4: ${ip}`);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function mask32FromLen(len) {
  const l = Number(len);
  if (!Number.isFinite(l) || l <= 0) return 0;
  if (l >= 32) return 0xFFFFFFFF >>> 0;
  return (0xFFFFFFFF << (32 - l)) >>> 0;
}

function deriveSameNetworkIpv4(peerAddr, networkLength, myPeerId) {
  const mask     = mask32FromLen(networkLength);
  const net      = (peerAddr >>> 0) & mask;
  const hostBits = 32 - Number(networkLength);
  if (!Number.isFinite(hostBits) || hostBits <= 1 || hostBits > 30) return null;
  const hostMax  = (1 << hostBits) >>> 0;
  const peerHost = (peerAddr >>> 0) & (~mask >>> 0);
  let host = (Number(myPeerId) % 250) + 2;
  if (host >= hostMax) host = (Number(myPeerId) % Math.max(hostMax - 2, 1)) + 1;
  if (host === peerHost) { host = (host + 1) % hostMax; if (host === 0) host = 1; }
  return (net | host) >>> 0;
}

function randomUint32() { return Math.floor(Math.random() * 4294967296); }
function makeInstId()   { return { part1: randomUint32(), part2: randomUint32(), part3: randomUint32(), part4: randomUint32() }; }

function makeStubPeerInfo(peerId, networkLength) {
  return {
    peerId,
    version:        1,
    lastUpdate:     { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
    instId:         makeInstId(),
    cost:           1,
    hostname:       'CF-ETSV',
    easytierVersion:'cf-et-ws',
    featureFlag:    { isPublicServer: false, avoidRelayData: false, kcpInput: false, noRelayKcp: false },
    networkLength:  Number(networkLength || 24),
    peerRouteId:    randomU64String(),
    groups:         [],
    udpStunInfo:    1,
  };
}

// ── PeerManager ───────────────────────────────────────────────────────────────

export class PeerManager {
  constructor() {
    this.peersByGroup     = new Map(); // groupKey -> Map(peerId -> ws)
    this.peerInfosByGroup = new Map(); // groupKey -> Map(peerId -> peerInfo)
    this.routeSessions    = new Map(); // groupKey -> Map(peerId -> session)
    this.peerConnVersions = new Map(); // groupKey -> Map(peerId -> version)
    this.types            = null;
    this._cfEnv           = null;

    this.allowVirtualIP  = false;
    this.ipAutoAssigned  = false;
    this.myInfo          = null;

    // [CF-env] 将在 setEnv() 后从 CF env 绑定更新; 此处安全默认值
    this.pureP2PMode      = false;
    this.sessionTtlMs     = 3 * 60 * 1000;
    this.lastSessionCleanup = 0;

    // [Version] 构造函数中初始化, 不再惰性初始化
    this.globalNetworkVersion = Math.floor(Date.now() / 1000) % 2_000_000_000;

    // [Bump] DO 批量恢复期间标志
    this._inHibernationRestore = false;
  }

  /**
   * 由 RelayRoom 构造函数调用, 注入 CF env 绑定。
   * [CF-env] CF Workers [vars] 只通过 env 对象访问, 不注入 process.env。
   */
  setEnv(env) {
    this._cfEnv = env || null;
    if (!env) return;
    this.pureP2PMode = env.EASYTIER_DISABLE_RELAY === '1';
    const ttl = Number(env.EASYTIER_SESSION_TTL_MS);
    if (Number.isFinite(ttl) && ttl > 0) this.sessionTtlMs = ttl;
  }

  setTypes(types) { this.types = types; }

  ensureMyInfo() {
    if (this.myInfo) return this.myInfo;
    const env = this._cfEnv || {};
    this.myInfo = {
      peerId:         MY_PEER_ID,
      instId:         makeInstId(),
      cost:           1,
      version:        1,
      featureFlag:    { isPublicServer: true, avoidRelayData: this.pureP2PMode, kcpInput: false, noRelayKcp: false },
      networkLength:  Number(env.EASYTIER_NETWORK_LENGTH || 24),
      easytierVersion:env.EASYTIER_VERSION || 'cf-et-ws',
      lastUpdate:     { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      hostname:       env.EASYTIER_HOSTNAME || 'CF-ETSV',
      udpStunInfo:    1,
      peerRouteId:    randomU64String(),
      groups:         [],
    };
    if (this.allowVirtualIP) {
      const ipEnv = env.EASYTIER_IPV4_ADDR;
      if (ipEnv) {
        this.myInfo.ipv4Addr = { addr: parseIpv4ToU32Be(ipEnv) };
      } else if (env.EASYTIER_AUTO_IPV4_ADDR === '1') {
        const oct = (Number(MY_PEER_ID) % 250) + 2;
        this.myInfo.ipv4Addr = { addr: parseIpv4ToU32Be(`10.0.0.${oct}`) };
        this.ipAutoAssigned = true;
      }
    }
    return this.myInfo;
  }

  bumpMyInfoVersion() {
    const m = this.ensureMyInfo();
    m.version = (m.version || 0) + 1;
    m.lastUpdate = { seconds: Math.floor(Date.now() / 1000), nanos: 0 };
  }

  // ── 内部 Map 工具 ────────────────────────────────────────────────────────────

  _getPeersMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peersByGroup.get(k);
    if (!m && create) { m = new Map(); this.peersByGroup.set(k, m); }
    return m;
  }

  _getPeerInfosMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peerInfosByGroup.get(k);
    if (!m && create) { m = new Map(); this.peerInfosByGroup.set(k, m); }
    return m;
  }

  _getPeerConnVersionMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peerConnVersions.get(k);
    if (!m && create) { m = new Map(); this.peerConnVersions.set(k, m); }
    return m;
  }

  // ── 版本号 ───────────────────────────────────────────────────────────────────

  bumpPeerConnVersion(groupKey, peerId) {
    const m = this._getPeerConnVersionMap(groupKey, true);
    const v = (m.get(peerId) || 0) + 1;
    m.set(peerId, v);
    return v;
  }

  getPeerConnVersion(groupKey, peerId) {
    const m = this._getPeerConnVersionMap(groupKey, false);
    return m ? (m.get(peerId) || 0) : 0;
  }

  bumpAllPeerConnVersions(groupKey) {
    const all = new Set(this.listPeerIdsInGroup(groupKey));
    const inf = this._getPeerInfosMap(groupKey, false);
    if (inf) for (const pid of inf.keys()) all.add(pid);
    all.add(MY_PEER_ID);
    for (const pid of all) this.bumpPeerConnVersion(groupKey, pid);
  }

  setPublicServerFlag(isPublicServer) {
    const m    = this.ensureMyInfo();
    const next = !!isPublicServer;
    const prev = !!(m.featureFlag && m.featureFlag.isPublicServer);
    m.featureFlag = { ...m.featureFlag, isPublicServer: next };
    if (next !== prev) this.bumpMyInfoVersion();
  }

  // ── Session ──────────────────────────────────────────────────────────────────

  _getSession(groupKey, peerId, create = false) {
    const now = Date.now();
    const interval = Math.max(30_000, Math.min(this.sessionTtlMs / 2, 120_000));
    if (now - this.lastSessionCleanup > interval) this.cleanupSessions(now);
    const gk = String(groupKey || '');
    let g = this.routeSessions.get(gk);
    if (!g && create) { g = new Map(); this.routeSessions.set(gk, g); }
    if (!g) return null;
    let s = g.get(peerId);
    if (!s && create) {
      s = { mySessionId: null, dstSessionId: null, weAreInitiator: false,
            peerInfoVerMap: new Map(), connBitmapVerMap: new Map(),
            foreignNetVer: 0, lastTouch: now, lastConnBitmapSig: null };
      g.set(peerId, s);
    }
    if (s) s.lastTouch = now;
    return s;
  }

  cleanupSessions(nowTs = Date.now()) {
    this.lastSessionCleanup = nowTs;
    for (const [gk, m] of this.routeSessions.entries()) {
      for (const [pid, s] of m.entries()) {
        if (nowTs - (s.lastTouch || 0) > this.sessionTtlMs) m.delete(pid);
      }
      if (m.size === 0) this.routeSessions.delete(gk);
    }
  }

  onRouteSessionAck(groupKey, peerId, theirSessionId, weAreInitiator) {
    const s = this._getSession(groupKey, peerId, true);
    const isNew = s.dstSessionId !== theirSessionId;
    if (isNew) {
      console.log(`[SessionAck] New session for peer ${peerId}, resetting version state`);
      s.peerInfoVerMap.clear();
      s.connBitmapVerMap.clear();
      s.foreignNetVer    = 0;
      s.lastConnBitmapSig = null;
      const cv = this._getPeerConnVersionMap(groupKey, true);
      cv.set(peerId, 1);
    }
    s.dstSessionId = theirSessionId;
    if (typeof weAreInitiator === 'boolean') s.weAreInitiator = weAreInitiator;
  }

  // ── Peer 注册 ────────────────────────────────────────────────────────────────

  /**
   * [H2]      groupKey 为空时跳过, 不污染空 key 桶。
   * [Ghost-1] 发现旧 WS 时设 isCleanedUp=true, 抑制旧 close 事件的所有清理动作。
   * [Bump]    批量恢复期间跳过 bump, 由 RelayRoom 构造函数统一处理。
   */
  addPeer(peerId, ws) {
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    if (!groupKey) {
      console.warn(`[PeerManager] addPeer: no groupKey for peer ${peerId}, skipping`);
      return;
    }
    const peers = this._getPeersMap(groupKey, true);
    const oldWs = peers.get(peerId);
    if (oldWs && oldWs !== ws) {
      console.log(`[PeerManager] Replacing stale WS for peer ${peerId}, suppressing old close event`);
      oldWs.isCleanedUp = true;
    }
    const isNew = !peers.has(peerId);
    peers.set(peerId, ws);
    if (isNew && !this._inHibernationRestore) this.bumpAllPeerConnVersions(groupKey);
  }

  /**
   * [H2]      groupKey 为空时仅清理 global_state, 跳过 Map 操作。
   * [Ghost-2] peers.get(peerId) !== ws 时返回 false, 防止旧 close 事件误删新连接。
   * [Return]  实际删除时才返回 true。
   */
  removePeer(ws) {
    const peerId   = ws && ws.peerId;
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    if (!peerId) return false;

    try { cleanPeerAndSubPeers(groupKey, peerId); } catch (e) {
      console.warn(`[PeerCleanup] cleanPeerAndSubPeers failed for ${peerId}:`, e.message);
    }

    if (!groupKey) {
      console.warn(`[PeerManager] removePeer: no groupKey for peer ${peerId}, skipping Map ops`);
      return false;
    }

    // [Ghost-2] 身份校验: 若 Map 中已是新 WS, 不删除
    const peers = this._getPeersMap(groupKey, false);
    if (!peers || peers.get(peerId) !== ws) {
      console.log(`[PeerCleanup] Stale close ignored for peer ${peerId}: newer WS already registered`);
      return false;
    }

    peers.delete(peerId);
    const infos = this._getPeerInfosMap(groupKey, false);
    if (infos) infos.delete(peerId);
    const sessions = this.routeSessions.get(groupKey);
    if (sessions) { sessions.delete(peerId); if (sessions.size === 0) this.routeSessions.delete(groupKey); }
    const cv = this._getPeerConnVersionMap(groupKey, false);
    if (cv) cv.delete(peerId);

    if (peers.size > 0) this.bumpAllPeerConnVersions(groupKey);

    if (peers.size === 0) {
      this.peersByGroup.delete(groupKey);
      this.peerInfosByGroup.delete(groupKey);
      this.peerConnVersions.delete(groupKey);
    }

    console.log(`[PeerCleanup] Removed peer ${peerId} from group ${groupKey}`);
    return true;
  }

  getPeerWs(peerId, groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? peers.get(peerId) : undefined;
  }

  listPeerIdsInGroup(groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? Array.from(peers.keys()) : [];
  }

  listPeersInGroup(groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? Array.from(peers.entries()) : [];
  }

  updatePeerInfo(groupKey, peerId, info) {
    const infos = this._getPeerInfosMap(groupKey, true);
    const isNew = !infos.has(peerId);
    infos.set(peerId, info);
    if (isNew) this.bumpAllPeerConnVersions(groupKey);

    // 虚拟 IP 自动分配 (allowVirtualIP 当前恒为 false, 保留扩展点)
    if (this.allowVirtualIP && !this._cfEnv?.EASYTIER_IPV4_ADDR && this.ipAutoAssigned) {
      const myInfo   = this.ensureMyInfo();
      const peerIpv4 = info?.ipv4Addr?.addr != null ? (info.ipv4Addr.addr >>> 0) : null;
      const netLen   = Number(info?.networkLength || info?.network_length || myInfo.networkLength || 24);
      if (peerIpv4 !== null && Number.isFinite(netLen) && netLen > 0) {
        const derived = deriveSameNetworkIpv4(peerIpv4, netLen, MY_PEER_ID);
        if (derived !== null) {
          let changed = false;
          if (!this._cfEnv?.EASYTIER_NETWORK_LENGTH && myInfo.networkLength !== netLen) {
            myInfo.networkLength = netLen; changed = true;
          }
          const prev = myInfo.ipv4Addr?.addr != null ? (myInfo.ipv4Addr.addr >>> 0) : null;
          if (prev !== derived) { myInfo.ipv4Addr = { addr: derived }; changed = true; }
          if (changed) { this.bumpMyInfoVersion(); this.ipAutoAssigned = false; }
        }
      }
    }
  }

  // ── 路由广播 ─────────────────────────────────────────────────────────────────

  /**
   * [Default] 默认 forceFull=false。
   * 原版 `opts.forceFull !== undefined ? !!opts.forceFull : true` 导致无参调用时触发全量广播。
   * 修复: 需要全量时必须显式传 { forceFull: true }。
   */
  broadcastRouteUpdate(types, groupKey, excludePeerId, opts = {}) {
    const forceFull = opts.forceFull === true;
    if (groupKey !== undefined) {
      const peers = this._getPeersMap(groupKey, false);
      if (!peers) return;
      for (const [peerId, ws] of peers.entries()) {
        if (peerId === excludePeerId) continue;
        if (ws.readyState === WS_OPEN) this.pushRouteUpdateTo(peerId, ws, types, { forceFull });
      }
      return;
    }
    for (const [, peers] of this.peersByGroup.entries()) {
      for (const [peerId, ws] of peers.entries()) {
        if (peerId === excludePeerId) continue;
        if (ws.readyState === WS_OPEN) this.pushRouteUpdateTo(peerId, ws, types, { forceFull });
      }
    }
  }

  pushRouteUpdateTo(targetPeerId, ws, types, opts = {}) {
    const forceFull  = !!opts.forceFull;
    const groupKey   = ws && ws.groupKey ? String(ws.groupKey) : '';
    const session    = this._getSession(groupKey, targetPeerId, true);
    const myInfo     = this.ensureMyInfo();
    const env        = this._cfEnv || {};

    if (!ws.serverSessionId) ws.serverSessionId = randomU64String();
    session.mySessionId  = ws.serverSessionId;
    const forceFullLocal = forceFull || !session.dstSessionId;

    // 收集所有相关 peer (直连 + 路由信息 + 全局子设备)
    const allPeers = new Set(this.listPeerIdsInGroup(groupKey));
    const infos    = this._getPeerInfosMap(groupKey, false);
    if (infos) for (const pid of infos.keys()) allPeers.add(pid);
    try {
      const gs = getPeerCenterState(groupKey);
      for (const [pid, pi] of gs.globalPeerMap.entries()) {
        allPeers.add(Number(pid));
        if (pi.directPeers) for (const sub of Object.keys(pi.directPeers)) allPeers.add(Number(sub));
      }
    } catch (e) {
      console.warn(`[RouteUpdate] Failed to read global peer state for ${groupKey}:`, e.message);
    }
    allPeers.add(targetPeerId);

    const relevantPeers = [
      MY_PEER_ID,
      ...Array.from(allPeers).filter(p => p !== MY_PEER_ID).sort((a, b) => Number(a) - Number(b))
    ];
    const defaultNetLen = myInfo.networkLength || 24;

    // peerInfosItems
    const peerInfosItems = [];
    for (const pid of relevantPeers) {
      let info = pid === MY_PEER_ID
        ? myInfo
        : this._getPeerInfosMap(groupKey, false)?.get(pid);

      if (!info && pid !== MY_PEER_ID) {
        try {
          const gs = getPeerCenterState(groupKey);
          const known = Array.from(gs.globalPeerMap.values()).some(
            pi => pi.directPeers && String(pid) in pi.directPeers
          );
          if (!known) continue;
        } catch (e) { continue; }
        info = makeStubPeerInfo(pid, defaultNetLen);
      }
      if (!info) continue;

      const version = info.version || 1;
      const prev    = forceFullLocal ? 0 : (session.peerInfoVerMap.get(pid) || 0);
      if (forceFullLocal || version > prev) {
        peerInfosItems.push(info);
        session.peerInfoVerMap.set(pid, version);
      }
    }

    // 连接位图 (全连接拓扑)
    let connBitmap = null;
    if (relevantPeers.length > 0) {
      const cv             = this._getPeerConnVersionMap(groupKey, true);
      const peerIdVersions = relevantPeers.map(pid => ({ peerId: pid, version: cv.get(pid) || 1 }));
      const N              = peerIdVersions.length;
      const bitmap         = new Uint8Array(Math.ceil((N * N) / 8));
      for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
        const idx = i * N + j;
        bitmap[Math.floor(idx / 8)] |= (1 << (idx % 8));
      }
      const bitmapBuf = Buffer.from(bitmap);
      const sig       = `${peerIdVersions.map(p => p.peerId).join(',')}|${bitmapBuf.toString('hex')}`;
      if (forceFullLocal || sig !== session.lastConnBitmapSig) {
        this.globalNetworkVersion += 1;
        session.lastConnBitmapSig  = sig;
        console.log(`[ConnBitmap] Topology changed, version -> ${this.globalNetworkVersion}`);
      }
      const ver = this.globalNetworkVersion;
      for (const pv of peerIdVersions) pv.version = ver;
      connBitmap = { peerIds: peerIdVersions, bitmap: bitmapBuf, version: ver };
    }

    // foreignNetworkInfos
    const foreignNetworkInfos = (() => {
      const mode = (env.EASYTIER_HANDSHAKE_MODE || 'foreign').toLowerCase();
      if (mode === 'same' || mode === 'same_network') return null;
      const version = session.foreignNetVer + 1;
      session.foreignNetVer = version;
      return {
        infos: [{
          key:   { peerId: MY_PEER_ID, networkName: env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME || 'dev-websocket-relay' },
          value: {
            foreignPeerIds:          Array.from(allPeers),
            lastUpdate:              { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
            version,
            networkSecretDigest:     Buffer.alloc(32),
            myPeerIdForThisNetwork:  MY_PEER_ID
          }
        }]
      };
    })();

    const t = this.types;
    if (!t) throw new Error('PeerManager types not set');

    const reqPayload = {
      myPeerId:           MY_PEER_ID,
      mySessionId:        ws.serverSessionId,
      isInitiator:        !!ws.weAreInitiator,
      peerInfos:          peerInfosItems.length > 0 ? { items: peerInfosItems } : null,
      rawPeerInfos:       peerInfosItems.length > 0 ? peerInfosItems.map(i => t.RoutePeerInfo.encode(i).finish()) : null,
      connBitmap,
      foreignNetworkInfos
    };

    const reqBytes    = t.SyncRouteInfoRequest.encode(reqPayload).finish();
    const rpcReqBytes = t.RpcRequest.encode({ request: reqBytes, timeoutMs: 5000 }).finish();
    const rpcPacket   = {
      fromPeer:      MY_PEER_ID,
      toPeer:        targetPeerId,
      transactionId: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
      descriptor:    {
        domainName:  ws.domainName || 'public_server',
        protoName:   'OspfRouteRpc',
        serviceName: 'OspfRouteRpc',
        // [CF-env] 从 CF env 绑定读取, 原版读 process.env 始终得到 undefined
        methodIndex: Number(env.EASYTIER_OSPF_ROUTE_METHOD_INDEX || 1)
      },
      body:          rpcReqBytes,
      isRequest:     true,
      totalPieces:   1,
      pieceIdx:      0,
      traceId:       0,
      compressionInfo: { algo: 1, acceptedAlgo: 1 }
    };

    try {
      ws.send(wrapPacket(createHeader, MY_PEER_ID, targetPeerId, PacketType.RpcReq,
        t.RpcPacket.encode(rpcPacket).finish(), ws));
    } catch (_) {}
  }
}

let peerManagerInstance = null;
export function getPeerManager() {
  if (!peerManagerInstance) peerManagerInstance = new PeerManager();
  return peerManagerInstance;
}
