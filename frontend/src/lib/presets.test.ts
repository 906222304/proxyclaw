import { describe, expect, it } from 'vitest'
import type { AutoRule, ProxyGroup } from '@/api/types'
import {
  APP_PRESETS,
  connectionToPrefill,
  filterPresets,
  isPresetInstalled,
  presetToPrefill,
  presetToRulePayload,
  processToPrefill,
} from './presets'

const groups: ProxyGroup[] = [
  { id: 0, name: 'Default', host: '127.0.0.1', port: 7890, type: 'socks5', test_url: '' },
  { id: 2, name: 'JP', host: '10.0.0.2', port: 1080, type: 'socks5', test_url: '' },
]

describe('editable app presets', () => {
  it('defines unique presets with valid process or Store package identity', () => {
    const ids = new Set(APP_PRESETS.map(p => p.id))
    expect(ids.size).toBe(APP_PRESETS.length)
    for (const p of APP_PRESETS) {
      expect(p.process_name || p.package_family_name).toBeTruthy()
    }
  })

  it('filters presets by category and search text including Store package family', () => {
    const ai = filterPresets(APP_PRESETS, 'ai', '')
    expect(ai.length).toBeGreaterThan(0)
    expect(ai.every(p => p.category === 'ai')).toBe(true)

    const storeMatches = filterPresets(APP_PRESETS, 'all', '8wekyb3d8bbwe')
    expect(storeMatches.map(p => p.id)).toEqual(['windows-terminal'])
  })

  it('converts a Store preset to an enabled RulePayload and editable RulePrefill', () => {
    const chatgpt = APP_PRESETS.find(p => p.id === 'chatgpt-store')!
    const payload = presetToRulePayload(chatgpt, groups)
    expect(payload).toMatchObject({
      name: chatgpt.name,
      enabled: true,
      process_name: 'ChatGPT.exe',
      package_family_name: 'OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0',
      hack_tree: true,
      proxy_group_id: 0,
      proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 },
    })

    const prefill = presetToPrefill(chatgpt)
    expect(prefill.packageFamilyName).toBe('OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0')
    expect(prefill.enabled).toBe(true)

    const installedRule = {
      id: 'r1',
      name: 'My ChatGPT',
      enabled: true,
      process_name: 'chatgpt.exe',
      cmdline_pattern: '',
      package_family_name: 'openai.chatgpt-desktop_2p2nqsd0c76g0',
      hack_tree: true,
      proxy_group_id: 0,
      proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 },
      dst_filter: { include_cidrs: [], exclude_cidrs: [], include_ports: [], exclude_ports: [] },
    } satisfies AutoRule
    expect(isPresetInstalled(chatgpt, [installedRule])).toBe(true)
  })

  it('builds prefills from network connections and prefers Store package identity over versioned path', () => {
    const storePrefill = connectionToPrefill(
      { process_name: 'WindowsTerminal.exe', protocol: 'TCP' },
      {
        image_path: 'C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.21.0.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe',
        package_family_name: 'Microsoft.WindowsTerminal_8wekyb3d8bbwe',
      },
    )
    expect(storePrefill).toEqual({
      name: 'WindowsTerminal.exe 的规则',
      processName: 'WindowsTerminal.exe',
      workDir: '',
      packageFamilyName: 'Microsoft.WindowsTerminal_8wekyb3d8bbwe',
      protocol: 'tcp',
    })

    const udpPrefill = connectionToPrefill(
      { process_name: 'Discord.exe', protocol: 'UDP' },
      { image_path: 'C:\\Users\\me\\AppData\\Local\\Discord\\app-1.0\\Discord.exe' },
    )
    expect(udpPrefill).toEqual({
      name: 'Discord.exe 的规则',
      processName: 'Discord.exe',
      workDir: 'C:\\Users\\me\\AppData\\Local\\Discord\\app-1.0\\',
      packageFamilyName: '',
      protocol: 'udp',
    })

    const procFallback = processToPrefill('curl.exe', null)
    expect(procFallback.processName).toBe('curl.exe')
    expect(procFallback.workDir).toBe('')
  })
})
