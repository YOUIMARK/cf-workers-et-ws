/**
 * Cloudflare Worker 入口
 *
 * 路由:
 *   GET  /healthz        → 健康检查
 *   GET  /admin/networks → 占位 (DO 内部状态)
 *   *    /{WS_PATH}      → WebSocket 升级 → RelayRoom DO
 *
 * 修复: globalNetworkState 已移除——原版该 Map 从未被写入,
 *       /admin/networks 始终返回空, 属于死代码。
 */
import { RelayRoom } from './worker/relay_room';
export { RelayRoom };

export default {
  async fetch(request, env) {
    const url      = new URL(request.url);
    const pathname = url.pathname;

    if (pathname === '/healthz') {
      return new Response('ok', { status: 200 });
    }

    if (pathname === '/admin/networks') {
      return new Response(JSON.stringify({ success: true, networks: [] }),
        { headers: { 'Content-Type': 'application/json' } });
    }

    // 修复: 原版 '/' + env.WS_PATH || '/ws' 运算符优先级错误
    // 当 WS_PATH 为 undefined 时得到 '/undefined' 而非 '/ws'
    const wsPath = env.WS_PATH ? `/${env.WS_PATH}` : '/ws';
    if (pathname === wsPath || pathname === `${wsPath}/`) {
      if (request.headers.get('Upgrade') !== 'websocket') {
        return new Response('Expected WebSocket upgrade', { status: 400 });
      }
      const roomId  = url.searchParams.get('room') || 'default';
      const options = env.LOCATION_HINT ? { locationHint: env.LOCATION_HINT } : {};
      const stub    = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId), options);
      return stub.fetch(request);
    }

    return new Response('Not found', { status: 404 });
  }
};
