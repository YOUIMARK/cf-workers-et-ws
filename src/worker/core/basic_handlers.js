/**
 * EasyTier 基础消息处理器
 *
 * 修复列表:
 * [H1] handleHandshake: 握手完成设置 peerId/groupKey 后立即重新调用
 *      serializeAttachment, 确保 DO 休眠恢复后 peer 不丢失。
 * [H4] 私有模式从 ws._env (CF env 绑定) 读取, 不再读 process.env。
 * [H3] isPublicServer 始终响应为 true, 防止 EasyTier 客户端触发 SecretKeyError。
 * [H7] catch 块: 先确认 e.message 存在再调用 includes, 修复运算符优先级 TypeError。
 * [H9] handleForwarding 转发失败时执行完整清理 (clearInterval + isCleanedUp +
 *      removeNetworkGroupActivity + removePeer), 不再绕过 _cleanup 导致资源泄漏。
 * [ND] 移除握手响应的 10ms setTimeout (CF Workers 无需等待客户端准备好)。
 * [NR] removeNetworkGroupActivity: 同步清理 networkDigestRegistry, 防止无界内存积累。
 * [BC] broadcastRouteUpdate 失败后使用 forceFull:false, 避免高频失败时广播风暴。
 */

import { MAGIC, VERSION, MY_PEER_ID, PacketType, WS_OPEN } from './constants.js';
import { createHeader } from './packet.js';
import { getPeerManager } from './peer_manager.js';
import { wrapPacket, randomU64String } from './crypto.js';

function getGroupKey(ws) {
  return (ws && ws.groupKey) ? String(ws.groupKey) : '';
}

/** networkName -> Set<digestHex> */
const networkDigestRegistry = new Map();
/** groupKey (networkName:digestHex) -> { createdAt, peerCount, lastActivity } */
const networkGroups = new Map();

export function updateNetworkGroupActivity(groupKey) {
  const g = networkGroups.get(groupKey);
  if (g) { g.lastActivity = Date.now(); g.peerCount = (g.peerCount ?? 0) + 1; }
}

export function removeNetworkGroupActivity(groupKey) {
  const g = networkGroups.get(groupKey);
  if (!g) return;
  g.peerCount = Math.max(0, (g.peerCount ?? 1) - 1);
  if (g.peerCount === 0 && Date.now() - g.lastActivity > 24 * 60 * 60 * 1000) {
    networkGroups.delete(groupKey);
    // [NR] 同步清理 networkDigestRegistry, 防止无界内存积累
    for (const [netName, digests] of networkDigestRegistry.entries()) {
      const prefix = `${netName}:`;
      if (groupKey.startsWith(prefix)) {
        const digestHex = groupKey.slice(prefix.length);
        digests.delete(digestHex);
        if (digests.size === 0) networkDigestRegistry.delete(netName);
        break;
      }
    }
    console.log(`[NetworkGroup] Cleaned up inactive group: ${groupKey}`);
  }
}

export function getNetworkGroupsByNetwork(networkName) {
  const groups = [];
  for (const [groupKey, g] of networkGroups.entries()) {
    if (groupKey.startsWith(`${networkName}:`)) groups.push({ groupKey, ...g });
  }
  return groups;
}

// ── 握手处理 ─────────────────────────────────────────────────────────────────

export function handleHandshake(ws, header, payload, types) {
  try {
    const req = types.HandshakeRequest.decode(payload);

    if (req.magic !== MAGIC) { ws.close(); return; }

    const clientNetworkName = req.networkName || '';

    // [H4] 从 ws._env (CF env 绑定) 读取; process.env 在 CF Workers 中不包含 [vars]
    const env                = ws._env || {};
    const privateNetworkName = env.EASYTIER_NETWORK_NAME || '';
    if (privateNetworkName && clientNetworkName !== privateNetworkName) {
      console.error(`[Private Mode] Rejected: expected "${privateNetworkName}", got "${clientNetworkName}"`);
      ws.close(1008, 'Network name mismatch');
      return;
    }

    // [H3] 始终以公开服务器身份响应。
    // EasyTier 客户端在 isPublicServer=true 时跳过 networkName 校验,
    // 若响应 isPublicServer=false 则触发 SecretKeyError。
    // 私有模式拦截 (上方) 已提前拒绝不匹配的连接, 此处保持协议兼容。
    const isPublicServer    = true;
    const serverNetworkName = 'public_server';

    const clientDigest = req.networkSecretDigrest
      ? Buffer.from(req.networkSecretDigrest)
      : Buffer.alloc(0);
    const digestHex = clientDigest.toString('hex');

    let existingDigests = networkDigestRegistry.get(clientNetworkName);
    if (!existingDigests) {
      existingDigests = new Set();
      networkDigestRegistry.set(clientNetworkName, existingDigests);
    }
    if (digestHex.length > 0 && !existingDigests.has(digestHex)) {
      existingDigests.add(digestHex);
      console.log(`[Handshake] New digest for network "${clientNetworkName}": ${digestHex}`);
    }

    const groupKey = `${clientNetworkName}:${digestHex}`;
    if (!networkGroups.has(groupKey)) {
      networkGroups.set(groupKey, { createdAt: Date.now(), peerCount: 0, lastActivity: Date.now() });
      console.log(`[Handshake] Created network group: ${groupKey}`);
    }

    ws.domainName = clientNetworkName;
    ws.groupKey   = groupKey;
    ws.peerId     = req.myPeerId;

    // [H1] 握手完成后重新序列化, 确保 DO 休眠恢复时 peerId/groupKey 不丢失。
    // _initSocket 调用时 peerId/groupKey 为 null, 初始序列化写入了空值。
    ws.serializeAttachment?.({
      peerId:          ws.peerId,
      groupKey:        ws.groupKey,
      domainName:      ws.domainName,
      serverSessionId: ws.serverSessionId,
    });

    const pm = getPeerManager();
    pm.addPeer(req.myPeerId, ws);
    updateNetworkGroupActivity(groupKey);
    pm.updatePeerInfo(ws.groupKey, req.myPeerId, {
      peerId:       req.myPeerId,
      version:      1,
      lastUpdate:   { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      instId:       { part1: 0, part2: 0, part3: 0, part4: 0 },
      networkLength: Number(env.EASYTIER_NETWORK_LENGTH || 24),
    });
    pm.setPublicServerFlag(isPublicServer);
    ws.crypto          = { enabled: false };
    ws.weAreInitiator  = ws.weAreInitiator !== undefined ? ws.weAreInitiator : false;

    // [ND] 移除 10ms 延迟, 直接发送握手响应
    if (ws.readyState !== WS_OPEN) {
      console.error(`[Handshake] WS not open for peer ${req.myPeerId}, state: ${ws.readyState}`);
      return;
    }
    const respPayload = {
      magic:                MAGIC,
      myPeerId:             MY_PEER_ID,
      version:              VERSION,
      networkName:          serverNetworkName,
      networkSecretDigrest: new Uint8Array(32),
    };
    const respBuffer = types.HandshakeRequest.encode(respPayload).finish();
    const respHeader = createHeader(MY_PEER_ID, req.myPeerId, PacketType.HandShake, respBuffer.length);
    try {
      ws.send(Buffer.concat([respHeader, Buffer.from(respBuffer)]));
      console.log(`[Handshake] Response sent to peer ${req.myPeerId}`);
    } catch (sendErr) {
      console.error(`[Handshake] Send failed for peer ${req.myPeerId}:`, sendErr);
      return;
    }

    // 50ms 后推送初始路由 (避免在握手帧尾立刻推大包)
    setTimeout(() => {
      try {
        if (ws.readyState === WS_OPEN) {
          pm.pushRouteUpdateTo(req.myPeerId, ws, types, { forceFull: true });
          pm.broadcastRouteUpdate(types, ws.groupKey, null, { forceFull: true });
          console.log(`[Handshake] Initial route updates sent to peer ${req.myPeerId}`);
        }
      } catch (e) {
        console.error(`[Handshake] Initial route update failed for ${req.myPeerId}:`, e.message);
      }
    }, 50);

  } catch (e) {
    console.error('[Handshake] Error:', e);
    // [H7] 先确认 e.message 存在, 再调用 includes。
    // 原版 `e.message && A || B` 中 B 在 e.message 为 undefined 时直接执行, 抛 TypeError。
    const msg = (e && e.message) ? e.message : '';
    if (msg.includes('decode') || msg.includes('Invalid')) ws.close();
    // 其他错误不立即关闭, 由心跳机制处理
  }
}

// ── Ping 处理 ────────────────────────────────────────────────────────────────

export function handlePing(ws, header, payload) {
  const msg = wrapPacket(createHeader, MY_PEER_ID, header.fromPeerId, PacketType.Pong, payload, ws);
  ws.send(msg);
}

// ── 转发处理 ─────────────────────────────────────────────────────────────────

/**
 * [H9] 转发失败时执行完整清理序列, 不再绕过 relay_room._cleanup:
 *   1. clearInterval (heartbeatInterval)
 *   2. isCleanedUp = true (防止后续 close 事件重复清理)
 *   3. removeNetworkGroupActivity (恢复 peerCount)
 *   4. removePeer (从 Map 中移除)
 *   5. broadcastRouteUpdate forceFull:false (incremental, 版本已 bump)
 */
export function handleForwarding(sourceWs, header, fullMessage, types) {
  const pm       = getPeerManager();
  const targetWs = pm.getPeerWs(header.toPeerId, getGroupKey(sourceWs));
  if (!targetWs || targetWs.readyState !== WS_OPEN) return;

  const srcGroup = getGroupKey(sourceWs);
  const dstGroup = getGroupKey(targetWs);
  if (srcGroup && dstGroup && srcGroup !== dstGroup) {
    console.warn(`[Forward] Cross-group blocked: ${srcGroup} -> ${dstGroup}`);
    return;
  }

  try {
    targetWs.send(fullMessage);
  } catch (e) {
    console.error(`[Forward] Failed to peer ${header.toPeerId}: ${e.message}`);
    // [H9] 完整清理序列
    if (targetWs.heartbeatInterval) {
      clearInterval(targetWs.heartbeatInterval);
      targetWs.heartbeatInterval = null;
    }
    targetWs.isCleanedUp = true;
    if (dstGroup) {
      try { removeNetworkGroupActivity(dstGroup); } catch (_) {}
    }
    pm.removePeer(targetWs);
    // [BC] forceFull:false — removePeer 已 bumpAllPeerConnVersions, 增量更新即可
    // [M1-fix] 使用 dstGroup 而非 srcGroup: 转发失败意味着目标 peer 失效, 应通知目标所在组
    if (dstGroup) {
      try { pm.broadcastRouteUpdate(types, dstGroup, null, { forceFull: false }); } catch (_) {}
    }
  }
}
