import type { AutoRule, ProcessInfo, Stats, TcpConnection, NetworkConnection, ProxyGroup, GroupInUseError, ProxyTestResult } from './types'

const BASE = '/api'

const JSON_HEADERS: HeadersInit = { 'Content-Type': 'application/json' }

function mergeHeaders(init?: RequestInit): HeadersInit {
  // Only attach JSON Content-Type when there is actually a body, since
  // body-less requests with Content-Type are unusual and have triggered
  // intermediary issues for us.
  const hasBody = init?.body != null
  return {
    ...(hasBody ? JSON_HEADERS : {}),
    ...(init?.headers as Record<string, string> | undefined),
  }
}

// The backend rejects /api requests without the per-launch session cookie
// (set by /api/session when the window opens). A 401 therefore means the page
// outlived its session, e.g. after ProxyClaw restarted.
function failureMessage(status: number, text: string): string {
  if (status === 401) return '会话已失效，请从托盘重新打开 ProxyClaw 窗口'
  return `请求失败（${status}）：${text}`
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    ...options,
    headers: mergeHeaders(options),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(failureMessage(res.status, text))
  }
  const text = await res.text()
  if (!text) {
    throw new Error(`请求失败：${url} 返回了空内容`)
  }
  return JSON.parse(text) as T
}

async function requestVoid(url: string, options?: RequestInit): Promise<void> {
  const res = await fetch(`${BASE}${url}`, {
    ...options,
    headers: mergeHeaders(options),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(failureMessage(res.status, text))
  }
}

// -- Processes --
// Note: bulk tree retrieval (formerly GET /api/processes) is delivered via
// WebView2 PostMessage; subscribe through useNotifications() in api/notify.ts
// to read `tree`. /detail endpoints remain for cmdline + image_path fetches.

export function getProcessDetail(pid: number): Promise<ProcessInfo> {
  return request<ProcessInfo>(`/processes/${pid}/detail`)
}

// -- Hijack --
// v0.9.0: backend ignores `tree` parameter (always tree-mode). The arg is kept
// for signature stability and to keep the call sites self-documenting.

export function hijackProcess(pid: number, tree = true, groupId = 0): Promise<void> {
  return requestVoid(`/hijack/${pid}`, {
    method: 'POST',
    body: JSON.stringify({ tree, group_id: groupId }),
  })
}

export function unhijackProcess(pid: number, tree = true): Promise<void> {
  const query = tree ? '?tree=true' : ''
  // body: '' makes the browser emit Content-Length: 0; cpp-httplib's
  // DELETE handling otherwise blocks for the full read_timeout (5 s).
  return requestVoid(`/hijack/${pid}${query}`, { method: 'DELETE', body: '' })
}

export function getHijackedProcesses(): Promise<ProcessInfo[]> {
  return request<ProcessInfo[]>('/hijack')
}

export function batchHijack(pids: number[], action: 'hijack' | 'unhijack', groupId = 0): Promise<void> {
  return requestVoid('/hijack/batch', {
    method: 'POST',
    body: JSON.stringify({ pids, action, group_id: groupId }),
  })
}

// -- TCP Connections --

export function getTcpConnections(pid?: number, signal?: AbortSignal): Promise<TcpConnection[]> {
  const query = pid == null ? '' : `?pid=${pid}`
  return request<TcpConnection[]>(`/tcp${query}`, { signal })
}

export function getUdpConnections(pid?: number, signal?: AbortSignal): Promise<TcpConnection[]> {
  const query = pid == null ? '' : `?pid=${pid}`
  return request<TcpConnection[]>(`/udp${query}`, { signal })
}

export async function getNetworkConnections(pid?: number, signal?: AbortSignal): Promise<NetworkConnection[]> {
  const [tcp, udp] = await Promise.all([
    getTcpConnections(pid, signal),
    getUdpConnections(pid, signal),
  ])
  return [
    ...tcp.map(c => ({ ...c, protocol: 'TCP' as const })),
    ...udp.map(c => ({ ...c, protocol: 'UDP' as const })),
  ]
}

// -- Auto Rules --

export function getAutoRules(): Promise<AutoRule[]> {
  return request<AutoRule[]>('/auto-rules')
}

export function createAutoRule(rule: Omit<AutoRule, 'id'>): Promise<AutoRule> {
  return request<AutoRule>('/auto-rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  })
}

export function updateAutoRule(id: string, rule: Partial<AutoRule>): Promise<AutoRule> {
  return request<AutoRule>(`/auto-rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(rule),
  })
}

export function deleteAutoRule(id: string): Promise<void> {
  return requestVoid(`/auto-rules/${id}`, { method: 'DELETE', body: '' })
}

export function excludePid(ruleId: string, pid: number): Promise<void> {
  return requestVoid(`/auto-rules/${ruleId}/exclude/${pid}`, { method: 'POST' })
}

export function unexcludePid(ruleId: string, pid: number): Promise<void> {
  return requestVoid(`/auto-rules/${ruleId}/exclude/${pid}`, { method: 'DELETE', body: '' })
}

// -- Config --

export function getConfig(): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>('/config')
}

export function updateConfig(config: Record<string, unknown>): Promise<void> {
  return requestVoid('/config', {
    method: 'PUT',
    body: JSON.stringify(config),
  })
}

// -- Proxy Groups --

export function getProxyGroups(): Promise<ProxyGroup[]> {
  return request<ProxyGroup[]>('/proxy-groups')
}

export function createProxyGroup(group: Omit<ProxyGroup, 'id'>): Promise<ProxyGroup> {
  return request<ProxyGroup>('/proxy-groups', {
    method: 'POST',
    body: JSON.stringify(group),
  })
}

export function updateProxyGroup(id: number, group: Partial<ProxyGroup>): Promise<void> {
  return requestVoid(`/proxy-groups/${id}`, {
    method: 'PUT',
    body: JSON.stringify(group),
  })
}

export async function deleteProxyGroup(id: number): Promise<{ success: boolean } | GroupInUseError> {
  const res = await fetch(`${BASE}/proxy-groups/${id}`, {
    method: 'DELETE',
    headers: mergeHeaders(),
    body: '',
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : { success: true }
  if (res.status === 409) return data as GroupInUseError
  if (!res.ok) throw new Error(`请求失败（${res.status}）：${JSON.stringify(data)}`)
  return data
}

export function migrateProxyGroup(id: number, targetGroupId: number): Promise<void> {
  return requestVoid(`/proxy-groups/${id}/migrate`, {
    method: 'POST',
    body: JSON.stringify({ target_group_id: targetGroupId }),
  })
}

export function testProxyGroup(id: number): Promise<ProxyTestResult> {
  return request<ProxyTestResult>(`/proxy-groups/${id}/test`, {
    method: 'POST',
  })
}

// -- Stats --

export function getStats(signal?: AbortSignal): Promise<Stats> {
  return request<Stats>('/stats', { signal })
}

// -- Shell --

export interface LogSnapshot {
  path: string
  text: string
  exists: boolean
  truncated: boolean
}

export function getLog(signal?: AbortSignal): Promise<LogSnapshot> {
  return request<LogSnapshot>('/logs', { signal, cache: 'no-store' })
}

export function revealFile(path: string): Promise<void> {
  return requestVoid('/shell/reveal', {
    method: 'POST',
    body: JSON.stringify({ path }),
  })
}

export function browseExe(): Promise<{ cancelled?: boolean; path?: string; dir?: string; name?: string }> {
  return request<{ cancelled?: boolean; path?: string; dir?: string; name?: string }>('/shell/browse-exe', {
    method: 'POST',
  })
}

// -- Autostart (Windows Task Scheduler ProxyClawAutoStart) --

export interface AutostartState {
  enabled: boolean
  start_minimized: boolean
}

export function getAutostart(): Promise<AutostartState> {
  return request<AutostartState>('/autostart')
}

export function setAutostart(state: AutostartState): Promise<AutostartState> {
  return request<AutostartState>('/autostart', {
    method: 'PUT',
    body: JSON.stringify(state),
  })
}
