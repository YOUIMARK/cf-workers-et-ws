/**
 * 全局 Peer 中心状态管理
 *
 * 每个 DO 实例独享一份内存 (CF DO 单线程, 跨实例不共享), 无并发问题。
 *
 * 注意: PEER_CENTER_TTL_MS 通过 process.env 读取。
 *       CF Workers [vars] 不注入 process.env, 始终使用默认值 180000ms。
 *       wrangler.toml 中未定义此变量, 因此行为符合预期。
 */
import { MY_PEER_ID } from './constants.js';

// groupKey -> { globalPeerMap: Map<string, PeerEntry>, digest: string, lastTouch: number }
const peerCenterStateByGroup = new Map();

const PEER_CENTER_TTL_MS =
  Number(process.env.EASYTIER_PEER_CENTER_TTL_MS || 180_000);
const PEER_CENTER_CLEAN_INTERVAL =
  Math.max(30_000, Math.min(PEER_CENTER_TTL_MS / 2, 120_000));

let lastPeerCenterClean = 0;

export function getPeerCenterState(groupKey) {
  const k = String(groupKey || '');
  let s = peerCenterStateByGroup.get(k);
  if (!s) {
    s = { globalPeerMap: new Map(), digest: '0' };
    peerCenterStateByGroup.set(k, s);
  }
  const now = Date.now();
  if (now - lastPeerCenterClean > PEER_CENTER_CLEAN_INTERVAL) _cleanPeerCenterState(now);
  s.lastTouch = now;
  return s;
}

function _cleanPeerCenterState(now = Date.now()) {
  lastPeerCenterClean = now;
  for (const [gk, s] of peerCenterStateByGroup.entries()) {
    for (const [pid, info] of s.globalPeerMap.entries()) {
      if (now - (info.lastSeen || 0) > PEER_CENTER_TTL_MS) s.globalPeerMap.delete(pid);
    }
    if (now - (s.lastTouch || 0) > PEER_CENTER_TTL_MS && s.globalPeerMap.size === 0) {
      peerCenterStateByGroup.delete(gk);
    }
  }
}

export function cleanPeerAndSubPeers(groupKey, peerId) {
  const state     = getPeerCenterState(groupKey);
  const peerIdStr = String(peerId);
  state.globalPeerMap.delete(peerIdStr);
  for (const [otherId, peerInfo] of state.globalPeerMap.entries()) {
    if (peerInfo.directPeers && peerInfo.directPeers[peerIdStr]) {
      delete peerInfo.directPeers[peerIdStr];
      console.log(`[GlobalCleanup] Removed sub-peer ${peerIdStr} from ${otherId}`);
    }
  }
}

export function calcPeerCenterDigestFromMap(mapObj) {
  let hash = 0n;
  const str = JSON.stringify(mapObj);
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5n) - hash) + BigInt(str.charCodeAt(i));
    hash &= 0xFFFFFFFFFFFFFFFFn;
  }
  return hash.toString();
}

/**
 * buildPeerCenterResponseMap
 *
 * 修复: 原版调用方 (rpc_handler.js) 未传入 peerManager 参数,
 *       导致 peerManager.listPeerIdsInGroup() 抛出 TypeError。
 *       此函数不自行 import getPeerManager 以避免循环依赖,
 *       调用方必须显式传入。
 *
 * @param {string} groupKey
 * @param {object} state        — getPeerCenterState() 的返回值
 * @param {object} peerManager  — PeerManager 实例 (必须传入)
 */
export function buildPeerCenterResponseMap(groupKey, state, peerManager) {
  if (!peerManager) {
    console.error('[PeerCenter] buildPeerCenterResponseMap: peerManager is required');
    return {};
  }

  const out           = {};
  const allKnown      = new Set();
  const directPeerIds = peerManager.listPeerIdsInGroup(groupKey);

  directPeerIds.forEach(id => allKnown.add(id));

  const infos = peerManager._getPeerInfosMap(groupKey, false);
  if (infos) for (const pid of infos.keys()) allKnown.add(pid);

  for (const [peerId, peerInfo] of state.globalPeerMap.entries()) {
    allKnown.add(Number(peerId));
    if (peerInfo.directPeers) {
      for (const sub of Object.keys(peerInfo.directPeers)) allKnown.add(Number(sub));
    }
  }

  for (const peerId of allKnown) {
    const key      = String(peerId);
    const existing = state.globalPeerMap.get(key);
    out[key] = { directPeers: {}, ...(existing ? { ...existing } : {}) };
    if (!out[key].directPeers) out[key].directPeers = {};

    if (directPeerIds.includes(peerId)) {
      out[key].directPeers[String(MY_PEER_ID)] = { latencyMs: 0 };
    }
    if (existing && existing.directPeers) {
      for (const [sub, info] of Object.entries(existing.directPeers)) {
        out[key].directPeers[sub] = { ...info };
      }
    }
  }
  return out;
}
