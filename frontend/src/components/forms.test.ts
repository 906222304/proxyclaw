import { describe, expect, it } from 'vitest'
import type { AutoRule, ProxyGroup } from '@/api/types'
import {
  buildConfigFilename,
  dnsPatch,
  dnsRecoveryText,
  dnsStatusText,
  interceptionErrorText,
  interceptionStatusText,
  parseImportedConfig,
  patchConfig,
} from './ConfigEditor'
import { filterLog } from './LogViewer'
import { failedLabel, groupFormSchema, groupFormToPayload, normalizeProxyHost, testTooltip } from './ProxiesTab'
import { formToPayload, ruleToForm } from './RuleEditorDialog'
import { filterRules } from './AutoRules'

const groups: ProxyGroup[] = [{ id: 2, name: 'HK', host: '10.0.0.1', port: 1080, type: 'socks5', test_url: '' }]

describe('rule editor mapping', () => {
  it('prefills from a process and maps back to the API payload', () => {
    const f = ruleToForm(null, 'app.exe', 'C:\\App\\')
    expect(f.processName).toBe('app.exe')
    expect(f.useWorkDir).toBe(true)
    const payload = formToPayload({ ...f, group: '2' }, groups, false)
    expect(payload).toMatchObject({
      process_name: 'app.exe', image_path_pattern: 'C:\\App\\', hack_tree: true, protocol: 'tcp',
      proxy_group_id: 2, proxy: { type: 'socks5', host: '10.0.0.1', port: 1080 }, enabled: false,
    })
  })

  it('custom proxy keeps the last group id and parses host:port', () => {
    const f = { ...ruleToForm(null), group: '2', custom: true, customHost: '127.0.0.1:9050' }
    const payload = formToPayload(f, groups, true)
    expect(payload.proxy_group_id).toBe(2)
    expect(payload.proxy).toEqual({ type: 'socks5', host: '127.0.0.1', port: 9050 })
  })

  it('round-trips an existing rule including Store package_family_name', () => {
    const rule: AutoRule = {
      id: 'r1', name: 'R', enabled: true, process_name: 'x.exe', cmdline_pattern: '--a',
      image_path_pattern: '', package_family_name: 'Microsoft.WindowsTerminal_8wekyb3d8bbwe',
      hack_tree: true, protocol: 'both', proxy_group_id: 2,
      proxy: { type: 'socks5', host: 'h', port: 1 },
      dst_filter: { include_cidrs: [], exclude_cidrs: ['10.0.0.0/8'], include_ports: ['443'], exclude_ports: [] },
      child_exclusions: [{ process_name: 'ssh.exe', cmdline_pattern: '', image_path_pattern: '' }],
    }
    const form = ruleToForm(rule)
    form.childExclusions.push({ process_name: '  ', cmdline_pattern: '', image_path_pattern: '' })
    const payload = formToPayload(form, groups, rule.enabled)
    expect(payload.dst_filter).toEqual(rule.dst_filter)
    expect(payload.child_exclusions).toEqual(rule.child_exclusions)
    expect(payload.image_path_pattern).toBe('')
    expect(payload.package_family_name).toBe('Microsoft.WindowsTerminal_8wekyb3d8bbwe')
    expect(payload.protocol).toBe('both')
  })

  it('maps a RulePrefill with Store package identity into the form', () => {
    const f = ruleToForm(null, '', '', {
      name: 'ChatGPT（Store 版）',
      processName: 'ChatGPT.exe',
      packageFamilyName: 'OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0',
      protocol: 'tcp',
      enabled: true,
    })
    expect(f.name).toBe('ChatGPT（Store 版）')
    expect(f.packageFamilyName).toBe('OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0')
    expect(f.useWorkDir).toBe(false)
  })

  it('filters rules by status and text', () => {
    const r = (id: string, enabled: boolean, name: string) => ({ id, enabled, name, process_name: `${name}.exe` }) as AutoRule
    const list = [r('1', true, 'Alpha'), r('2', false, 'beta')]
    expect(filterRules(list, 'active', '').map(x => x.id)).toEqual(['1'])
    expect(filterRules(list, 'all', 'BETA').map(x => x.id)).toEqual(['2'])
  })
})

describe('settings helpers', () => {
  it('dns patch fills listen defaults without touching other keys', () => {
    const before = { dns: { listen_port: 5353 }, other: 1 }
    const next = patchConfig(before, dnsPatch(true, 'forwarder', '1.1.1.1'))
    expect(next).toEqual({
      other: 1,
      dns: { enabled: true, mode: 'forwarder', upstream_host: '1.1.1.1', upstream_port: 53, listen_host: '127.0.0.2', listen_port: 5353 },
    })
    expect(before.dns).toEqual({ listen_port: 5353 })
  })

  it('log filter keeps warning and error lines', () => {
    const text = '2026-11-03 10:00:00 [I] a\n2026-11-03 10:00:01 [W] b\n2026-11-03 10:00:02 [ERROR] c'
    expect(filterLog(text, '', 'problems').split('\n')).toHaveLength(2)
    expect(filterLog(text, 'B', 'all')).toContain('[W] b')
  })

  it('speed test labels', () => {
    expect(testTooltip({ latency_ms: 50, stages: [{ name: 'connect', ms: 10 }], detail: 'HTTP 204' }))
      .toBe('连接代理：10 ms\n合计 50 ms（HTTP 204）')
    expect(failedLabel({ failed_stage: 'handshake', error: 'x' })).toBe('SOCKS5 握手失败')
  })
})

describe('proxy group form validation', () => {
  const base = { name: 'g', host: '127.0.0.1', port: '1080', test_url: '', user: '', password: '' }
  const issues = (f: typeof base) => {
    const r = groupFormSchema.safeParse(f)
    return r.success ? [] : r.error.issues.map(i => `${String(i.path[0])}: ${i.message}`)
  }

  it('rejects ports outside 1-65535 and non-integers instead of defaulting', () => {
    for (const port of ['0', '65536', '70000', 'abc', '', '80.5', '-1', '1e3']) {
      expect(issues({ ...base, port }).some(m => m.startsWith('port:')), port).toBe(true)
    }
    for (const port of ['1', '1080', '65535', ' 7890 ']) {
      expect(issues({ ...base, port }), port).toEqual([])
    }
  })

  it('rejects an empty host and host:port, accepts IPv6 literals with or without brackets', () => {
    expect(issues({ ...base, host: '  ' }).some(m => m.startsWith('host:'))).toBe(true)
    expect(issues({ ...base, host: '10.0.0.1:1080' }).some(m => m.startsWith('host:'))).toBe(true)
    expect(issues({ ...base, host: 'a b' }).some(m => m.startsWith('host:'))).toBe(true)
    expect(issues({ ...base, host: '[::1]' })).toEqual([])
    expect(issues({ ...base, host: '2001:db8::1' })).toEqual([])
    expect(issues({ ...base, host: 'proxy.example.com' })).toEqual([])
  })

  it('validates optional RFC 1929 credentials (<= 255 UTF-8 bytes) and maps payload', () => {
    expect(normalizeProxyHost(' [::1] ')).toBe('::1')
    expect(issues({ ...base, user: 'alice', password: 'secret' })).toEqual([])
    expect(issues({ ...base, user: 'a'.repeat(256) }).some(m => m.startsWith('user:'))).toBe(true)
    expect(issues({ ...base, password: '中'.repeat(86) }).some(m => m.startsWith('password:'))).toBe(true)
    expect(groupFormToPayload({ ...base, host: '[::1]', port: ' 1080 ', user: 'alice', password: 'pw' })).toEqual({
      name: 'g', host: '::1', port: 1080, type: 'socks5', test_url: '', user: 'alice', password: 'pw',
    })
  })
})

describe('DNS status line', () => {
  it('shows progress, TCP-only mode and the failure reason', () => {
    expect(dnsStatusText(undefined)).toBe('')
    expect(dnsStatusText({ state: 'off' })).toBe('')
    expect(dnsStatusText({ state: 'starting' })).toBe('启动中…')
    expect(dnsStatusText({ state: 'running' })).toBe('运行中')
    expect(dnsStatusText({ state: 'running', tcp_only: true })).toContain('仅经 TCP')
    expect(dnsStatusText({ state: 'failed', error: 'proxy_unreachable' })).toContain('代理不可用')
    expect(dnsStatusText({ state: 'failed', error: 'something_new' })).toBe('启动失败：something_new')
  })
})

describe('interception status line', () => {
  it('says when a saved mode waits for a restart, and when the running one failed', () => {
    expect(interceptionStatusText('hook', undefined)).toBe('')
    expect(interceptionStatusText('windivert', { mode: 'windivert', active: true })).toBe('')
    expect(interceptionStatusText('hook', { mode: 'windivert', active: true })).toBe('重启 ProxyClaw 后生效（当前：WinDivert 驱动）')
    expect(interceptionStatusText('windivert', { mode: 'hook', active: true })).toContain('Hook 注入')
    expect(interceptionStatusText('hook', { mode: 'hook', active: false })).toContain('启动失败')
    expect(interceptionStatusText('windivert', { mode: 'windivert', active: false, error: 'windivert_driver_failed' }))
      .toContain('WinDivert 驱动加载失败')
    expect(interceptionErrorText('windivert_socket_failed', 'windivert')).toContain('TCP 套接字层')
  })
})

describe('engine status and config import/export helpers', () => {
  it('formats DNS recovery notices', () => {
    expect(dnsRecoveryText(undefined)).toBe('')
    expect(dnsRecoveryText('recovered')).toContain('自动恢复')
    expect(dnsRecoveryText('failed')).toContain('恢复失败')
  })

  it('builds a date-stamped config export filename', () => {
    expect(buildConfigFilename(new Date(2026, 10, 5))).toBe('proxyclaw-config-20261105.json')
  })

  it('parses valid config objects and rejects arrays or invalid JSON', () => {
    expect(parseImportedConfig('{"version": 2}')).toEqual({ version: 2 })
    expect(() => parseImportedConfig('{bad')).toThrow('JSON 格式无效')
    expect(() => parseImportedConfig('[1, 2]')).toThrow('JSON 对象')
    expect(() => parseImportedConfig('null')).toThrow('JSON 对象')
  })
})
