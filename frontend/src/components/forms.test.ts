import { describe, expect, it } from 'vitest'
import type { AutoRule, ProxyGroup } from '@/api/types'
import { dnsPatch, patchConfig } from './ConfigEditor'
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

  it('round-trips an existing rule', () => {
    const rule: AutoRule = {
      id: 'r1', name: 'R', enabled: true, process_name: 'x.exe', cmdline_pattern: '--a',
      image_path_pattern: '', hack_tree: true, protocol: 'both', proxy_group_id: 2,
      proxy: { type: 'socks5', host: 'h', port: 1 },
      dst_filter: { include_cidrs: [], exclude_cidrs: ['10.0.0.0/8'], include_ports: ['443'], exclude_ports: [] },
    }
    const payload = formToPayload(ruleToForm(rule), groups, rule.enabled)
    expect(payload.dst_filter).toEqual(rule.dst_filter)
    expect(payload.image_path_pattern).toBe('')
    expect(payload.protocol).toBe('both')
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
  const base = { name: 'g', host: '127.0.0.1', port: '1080', test_url: '' }
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

  it('normalises the host and sends a numeric port, socks5 only', () => {
    expect(normalizeProxyHost(' [::1] ')).toBe('::1')
    expect(groupFormToPayload({ ...base, host: '[::1]', port: ' 1080 ' })).toEqual({
      name: 'g', host: '::1', port: 1080, type: 'socks5', test_url: '',
    })
  })
})
