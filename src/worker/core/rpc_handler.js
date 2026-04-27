import { MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { getPeerManager } from './peer_manager.js';
import { wrapPacket, randomU64String } from './crypto.js';
import { gzipMaybe, gunzipMaybe, isCompressionAvailable } from './compress.js';
import { getPeerCenterState, calcPeerCenterDigestFromMap, buildPeerCenterResponseMap } from './global_state.js';

const COMPRESS_THRESHOLD = 256; // bytes; 小包不压缩

// ── toLongForProto ────────────────────────────────────────────────────────────

function toLongForProto(value) {
  if (value === null || value === undefined) return value;
  if (value && typeof value === 'object' && typeof value.low === 'number' && typeof value.high === 'number') return value;
  if (value && typeof value === 'object' && value.constructor?.name === 'Long') return value;
  if (typeof value === 'string') {
    try {
      const big = BigInt(value);
      return { low: Number(big & 0xffffffffn), high: Number((big >> 32n) & 0xffffffffn), unsigned: false };
    } catch { return value; }
  }
  if (typeof value === 'number') return { low: value | 0, high: Math.floor(value / 4294967296), unsigned: false };
  if (typeof value === 'bigint')  return { low: Number(value & 0xffffffffn), high: Number((value >> 32n) & 0xffffffffn), unsigned: false };
  return value;
}

function pm() { return getPeerManager(); }

// ── RPC 响应发送 ──────────────────────────────────────────────────────────────

function sendRpcResponse(ws, toPeerId, reqRpcPacket, types, responseBodyBytes) {
  if (!ws || ws.readyState !== 1) {
    console.error(`sendRpcResponse aborted: socket not open, toPeer=${toPeerId}`);
    return;
  }
  // [CF-env] 从 ws._env 读取压缩配置。原版 process.env.EASYTIER_COMPRESS_RPC 在 CF Workers
  // 中始终为 undefined, 导致压缩开关无法通过 wrangler.toml 控制。
  const env           = ws._env || {};
  const compressEnabled = env.EASYTIER_COMPRESS_RPC !== '0';

  let responseBody    = responseBodyBytes;
  let compressionInfo = { algo: 1, acceptedAlgo: 1 };
  if (compressEnabled && responseBodyBytes?.length > COMPRESS_THRESHOLD && isCompressionAvailable()) {
    try {
      responseBody    = gzipMaybe(responseBodyBytes);
      compressionInfo = { algo: 2, acceptedAlgo: 1 };
    } catch (e) { console.warn(`Compress RPC response failed: ${e.message}`); }
  }

  const rpcRespBytes = types.RpcResponse.encode({ response: responseBody, error: null, runtimeUs: 0 }).finish();
  const rpcPacket    = {
    fromPeer:       MY_PEER_ID,
    toPeer:         toPeerId,
    transactionId:  toLongForProto(reqRpcPacket.transactionId),
    descriptor:     reqRpcPacket.descriptor,
    body:           rpcRespBytes,
    isRequest:      false,
    totalPieces:    1,
    pieceIdx:       0,
    traceId:        reqRpcPacket.traceId,
    compressionInfo,
  };
  const buf = wrapPacket(createHeader, MY_PEER_ID, toPeerId, PacketType.RpcResp,
    types.RpcPacket.encode(rpcPacket).finish(), ws);
  try {
    ws.send(buf);
  } catch (e) {
    console.error(`sendRpcResponse to ${toPeerId} failed: ${e.message}`);
    throw new Error(`Failed to send RPC response to ${toPeerId}: ${e.message}`);
  }
}

// ── handleRpcReq ─────────────────────────────────────────────────────────────

export function handleRpcReq(ws, header, payload, types) {
  try {
    const rpcPacket = types.RpcPacket.decode(payload);

    if (rpcPacket.compressionInfo?.algo > 1 && isCompressionAvailable()) {
      try { rpcPacket.body = gunzipMaybe(rpcPacket.body); rpcPacket.compressionInfo.algo = 1; }
      catch (e) { console.error(`RpcPacket decompress failed from ${header.fromPeerId}: ${e.message}`); return; }
    }

    const descriptor = rpcPacket.descriptor;
    let innerReqBody = rpcPacket.body;
    try {
      const wrapper = types.RpcRequest.decode(rpcPacket.body);
      if (wrapper.request?.length > 0) innerReqBody = wrapper.request;
    } catch (e) { /* raw body */ }

    // ── PeerCenterRpc ──────────────────────────────────────────────────────────
    if ((descriptor.serviceName === 'peer_rpc.PeerCenterRpc' || descriptor.serviceName === 'PeerCenterRpc')
      && (descriptor.protoName === 'peer_rpc' || !descriptor.protoName)) {

      const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
      const state    = getPeerCenterState(groupKey);

      if (descriptor.methodIndex === 0) {
        // ReportPeers
        const req         = types.ReportPeersRequest.decode(innerReqBody);
        const directPeers = {};
        if (req.peerInfos?.directPeers) {
          for (const [dst, info] of Object.entries(req.peerInfos.directPeers)) {
            directPeers[String(dst)] = { latencyMs: (typeof info?.latencyMs === 'number') ? info.latencyMs : 0 };
          }
        }
        state.globalPeerMap.set(String(req.myPeerId), { directPeers, lastSeen: Date.now() });
        // [H8] 传入 pm() 作为第三参数; 原版遗漏导致 TypeError
        const snapshot = buildPeerCenterResponseMap(groupKey, state, pm());
        state.digest   = calcPeerCenterDigestFromMap(snapshot);
        sendRpcResponse(ws, header.fromPeerId, rpcPacket, types, types.ReportPeersResponse.encode({}).finish());
        return;
      }

      if (descriptor.methodIndex === 1) {
        // GetGlobalPeerMap
        const req       = types.GetGlobalPeerMapRequest.decode(innerReqBody);
        const reqDigest = (req.digest != null) ? String(req.digest) : '0';
        if (reqDigest === state.digest && reqDigest !== '0') {
          sendRpcResponse(ws, header.fromPeerId, rpcPacket, types, types.GetGlobalPeerMapResponse.encode({}).finish());
          return;
        }
        // [H8] 传入 pm()
        const snapshot = buildPeerCenterResponseMap(groupKey, state, pm());
        state.digest   = calcPeerCenterDigestFromMap(snapshot);
        sendRpcResponse(ws, header.fromPeerId, rpcPacket, types,
          types.GetGlobalPeerMapResponse.encode({ globalPeerMap: snapshot, digest: state.digest }).finish());
        return;
      }

      console.log(`Unhandled PeerCenterRpc methodIndex=${descriptor.methodIndex}`);
      return;
    }

    // ── OspfRouteRpc ───────────────────────────────────────────────────────────
    if ((descriptor.serviceName === 'peer_rpc.OspfRouteRpc' || descriptor.serviceName === 'OspfRouteRpc')
      && (descriptor.protoName === 'peer_rpc' || descriptor.protoName === 'peer_rpc.OspfRouteRpc'
          || descriptor.protoName === 'OspfRouteRpc' || !descriptor.protoName)) {

      const req = types.SyncRouteInfoRequest.decode(innerReqBody);
      if (descriptor.methodIndex === 0 || descriptor.methodIndex === 1) {
        handleSyncRouteInfo(ws, header.fromPeerId, rpcPacket, req, types);
        return;
      }
      console.log(`Unhandled OspfRouteRpc methodIndex=${descriptor.methodIndex}`);
      return;
    }

    console.log(`Unhandled RPC: ${descriptor.serviceName} proto=${descriptor.protoName}`);
  } catch (e) {
    console.error('RPC Decode error:', e);
  }
}

// ── handleRpcResp ─────────────────────────────────────────────────────────────

export function handleRpcResp(ws, header, payload, types) {
  try {
    const rpcPacket = types.RpcPacket.decode(payload);

    if (rpcPacket.compressionInfo?.algo > 1 && isCompressionAvailable()) {
      try { rpcPacket.body = gunzipMaybe(rpcPacket.body); rpcPacket.compressionInfo.algo = 1; }
      catch (e) { console.error(`RpcResp decompress failed from ${header.fromPeerId}: ${e.message}`); return; }
    }

    const descriptor = rpcPacket.descriptor || {};
    let rpcRespBody  = rpcPacket.body;
    let decoded      = null;
    try {
      decoded      = types.RpcResponse.decode(rpcRespBody);
      rpcRespBody  = decoded.response || rpcRespBody;
    } catch (e) { /* keep raw */ }

    if ((descriptor.serviceName === 'peer_rpc.OspfRouteRpc' || descriptor.serviceName === 'OspfRouteRpc')
      && (descriptor.protoName === 'peer_rpc' || descriptor.protoName === 'peer_rpc.OspfRouteRpc'
          || descriptor.protoName === 'OspfRouteRpc' || !descriptor.protoName)) {
      try {
        const resp      = types.SyncRouteInfoResponse.decode(rpcRespBody);
        const sessionId = resp?.sessionId || null;
        if (sessionId && ws?.groupKey !== undefined) {
          pm().onRouteSessionAck(ws.groupKey, header.fromPeerId, sessionId, ws.weAreInitiator);
        }
      } catch (e) {
        console.error(`Decode SyncRouteInfoResponse failed from ${header.fromPeerId}: ${e.message}`);
      }
      return;
    }

    if (decoded?.error) console.warn(`RpcResp error from ${header.fromPeerId}:`, decoded.error);
  } catch (e) {
    console.error('RPC Resp Decode error:', e);
  }
}

// ── handleSyncRouteInfo ───────────────────────────────────────────────────────

function handleSyncRouteInfo(ws, fromPeerId, reqRpcPacket, syncReq, types) {
  const groupKey = (ws && ws.groupKey) ? String(ws.groupKey) : '';
  if (!ws.serverSessionId) ws.serverSessionId = randomU64String();
  if (typeof syncReq.isInitiator === 'boolean') ws.weAreInitiator = !syncReq.isInitiator;

  const peerMgr = pm();
  peerMgr.onRouteSessionAck(groupKey, fromPeerId, syncReq.mySessionId, ws.weAreInitiator);

  let hasNewPeers = false;
  let hasSubPeers = false;

  if (syncReq.peerInfos?.items) {
    const items = syncReq.peerInfos.items;

    // [Bug1] isNew 检查必须在 updatePeerInfo 写入之前; 原版写入后再检查永远为 true
    // [Bug2] listPeerIdsInGroup 和 Set 构造提到循环外, 避免 O(n²)
    const existingInfos  = peerMgr._getPeerInfosMap(groupKey, false);
    const directSet      = new Set(peerMgr.listPeerIdsInGroup(groupKey));
    // [R4] 在第一次遍历中收集 subPeerEntries, 消除第二次遍历
    const subPeerEntries = {};

    for (const info of items) {
      if (!info.udpStunInfo || info.udpStunInfo === 0) info.udpStunInfo = 3;

      if (info.peerId !== MY_PEER_ID) {
        const isNew = !existingInfos || !existingInfos.has(info.peerId);
        if (isNew) hasNewPeers = true;
        if (!directSet.has(info.peerId)) {
          hasSubPeers = true;
          subPeerEntries[String(info.peerId)] = { latencyMs: 10 };
          console.log(`[SyncRoute] Sub-peer ${info.peerId} via ${fromPeerId}`);
        }
      }
      peerMgr.updatePeerInfo(groupKey, info.peerId, info);
    }

    if (hasSubPeers && Object.keys(subPeerEntries).length > 0) {
      const state = getPeerCenterState(groupKey);
      state.globalPeerMap.set(String(fromPeerId), { directPeers: subPeerEntries, lastSeen: Date.now() });
    }
  }

  // 先发响应, 再推路由
  const respBytes = types.SyncRouteInfoResponse.encode({
    isInitiator: !syncReq.isInitiator,
    sessionId:   ws.serverSessionId
  }).finish();
  try {
    sendRpcResponse(ws, fromPeerId, reqRpcPacket, types, respBytes);
  } catch (e) {
    console.error(`CRITICAL: SyncRouteInfoResponse send failed to ${fromPeerId}: ${e.message}`);
  }

  try { peerMgr.pushRouteUpdateTo(fromPeerId, ws, types, { forceFull: true }); }
  catch (e) { console.error(`pushRouteUpdateTo ${fromPeerId} failed:`, e); }

  if (hasNewPeers || hasSubPeers) {
    try { peerMgr.broadcastRouteUpdate(types, groupKey, fromPeerId, { forceFull: true }); }
    catch (e) { console.error(`broadcastRouteUpdate for ${groupKey} failed:`, e); }
  }
}
