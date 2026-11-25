import type { RulePayload } from '@/api/mutations'
import type { AutoRule, NetworkConnection, ProcessInfo, ProxyGroup, RuleProtocol } from '@/api/types'
import { dirOf, exeFromCmdline } from '@/lib/process'

export type PresetCategory = 'ai' | 'ide' | 'browser' | 'social'

export const PRESET_CATEGORIES: { key: PresetCategory | 'all'; label: string }[] = [
  { key: 'all', label: '全部' },
  { key: 'ai', label: 'AI 客户端' },
  { key: 'ide', label: '开发与终端' },
  { key: 'browser', label: '浏览器' },
  { key: 'social', label: '通讯与工具' },
]

export interface AppPreset {
  id: string
  category: PresetCategory
  name: string
  description: string
  process_name: string
  cmdline_pattern?: string
  image_path_pattern?: string
  /** Microsoft Store / MSIX PackageFamilyName — survives Store version upgrades. */
  package_family_name?: string
  protocol: RuleProtocol
}

export interface RulePrefill {
  name?: string
  processName?: string
  workDir?: string
  cmdlinePattern?: string
  packageFamilyName?: string
  protocol?: RuleProtocol
  enabled?: boolean
}

export const APP_PRESETS: AppPreset[] = [
  // AI 客户端 / CLI
  {
    id: 'claude-desktop',
    category: 'ai',
    name: 'Claude Desktop',
    description: 'Anthropic Claude 桌面客户端及其子进程',
    process_name: 'Claude.exe',
    protocol: 'tcp',
  },
  {
    id: 'chatgpt-store',
    category: 'ai',
    name: 'ChatGPT（Store 版）',
    description: '按 Store 包身份匹配，商店自动升级后仍有效',
    process_name: 'ChatGPT.exe',
    package_family_name: 'OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0',
    protocol: 'tcp',
  },
  {
    id: 'cursor',
    category: 'ai',
    name: 'Cursor',
    description: 'Cursor AI 编辑器及其扩展/终端子进程',
    process_name: 'Cursor.exe',
    protocol: 'tcp',
  },
  {
    id: 'windsurf',
    category: 'ai',
    name: 'Windsurf',
    description: 'Windsurf AI 编辑器及其子进程',
    process_name: 'Windsurf.exe',
    protocol: 'tcp',
  },
  {
    id: 'claude-code',
    category: 'ai',
    name: 'Claude Code CLI',
    description: '仅匹配命令行包含 claude 的 node.exe，避免误伤其他 Node 进程',
    process_name: 'node.exe',
    cmdline_pattern: 'claude',
    protocol: 'tcp',
  },
  {
    id: 'codex-cli',
    category: 'ai',
    name: 'Codex CLI',
    description: 'OpenAI Codex 命令行客户端',
    process_name: 'codex.exe',
    protocol: 'tcp',
  },

  // 开发与终端
  {
    id: 'vscode',
    category: 'ide',
    name: 'Visual Studio Code',
    description: 'VS Code 编辑器及其扩展、集成终端子进程',
    process_name: 'Code.exe',
    protocol: 'tcp',
  },
  {
    id: 'windows-terminal',
    category: 'ide',
    name: 'Windows Terminal（Store 版）',
    description: '按 Store 包身份匹配，包含终端内启动的命令行工具',
    process_name: 'WindowsTerminal.exe',
    package_family_name: 'Microsoft.WindowsTerminal_8wekyb3d8bbwe',
    protocol: 'tcp',
  },
  {
    id: 'jetbrains-idea',
    category: 'ide',
    name: 'IntelliJ IDEA',
    description: 'JetBrains IDEA 及构建/插件子进程',
    process_name: 'idea64.exe',
    protocol: 'tcp',
  },
  {
    id: 'jetbrains-pycharm',
    category: 'ide',
    name: 'PyCharm',
    description: 'JetBrains PyCharm 及解释器子进程',
    process_name: 'pycharm64.exe',
    protocol: 'tcp',
  },
  {
    id: 'git',
    category: 'ide',
    name: 'Git',
    description: 'git.exe 及 git-remote-https 等传输子进程',
    process_name: 'git.exe',
    protocol: 'tcp',
  },

  // 浏览器
  {
    id: 'chrome',
    category: 'browser',
    name: 'Google Chrome',
    description: 'Chrome 浏览器（TCP + UDP / QUIC）',
    process_name: 'chrome.exe',
    protocol: 'both',
  },
  {
    id: 'edge',
    category: 'browser',
    name: 'Microsoft Edge',
    description: 'Edge 浏览器（TCP + UDP / QUIC）',
    process_name: 'msedge.exe',
    protocol: 'both',
  },
  {
    id: 'firefox',
    category: 'browser',
    name: 'Mozilla Firefox',
    description: 'Firefox 浏览器（TCP + UDP / QUIC）',
    process_name: 'firefox.exe',
    protocol: 'both',
  },
  {
    id: 'brave',
    category: 'browser',
    name: 'Brave Browser',
    description: 'Brave 浏览器（TCP + UDP / QUIC）',
    process_name: 'brave.exe',
    protocol: 'both',
  },

  // 通讯与工具
  {
    id: 'telegram',
    category: 'social',
    name: 'Telegram',
    description: 'Telegram 桌面客户端（TCP + UDP 语音）',
    process_name: 'Telegram.exe',
    protocol: 'both',
  },
  {
    id: 'discord',
    category: 'social',
    name: 'Discord',
    description: 'Discord 客户端（TCP + UDP 语音）',
    process_name: 'Discord.exe',
    protocol: 'both',
  },
]

export function filterPresets(presets: AppPreset[], category: PresetCategory | 'all', query: string): AppPreset[] {
  const q = query.toLowerCase().trim()
  return presets.filter(p => {
    if (category !== 'all' && p.category !== category) return false
    if (!q) return true
    return p.name.toLowerCase().includes(q)
      || p.description.toLowerCase().includes(q)
      || p.process_name.toLowerCase().includes(q)
      || (p.package_family_name ?? '').toLowerCase().includes(q)
  })
}

export function presetToPrefill(preset: AppPreset): RulePrefill {
  return {
    name: preset.name,
    processName: preset.process_name,
    workDir: preset.image_path_pattern ?? '',
    cmdlinePattern: preset.cmdline_pattern ?? '',
    packageFamilyName: preset.package_family_name ?? '',
    protocol: preset.protocol,
    enabled: true,
  }
}

export function presetToRulePayload(preset: AppPreset, groups: ProxyGroup[]): RulePayload {
  const g = groups.find(x => x.id === 0) ?? groups[0]
  return {
    name: preset.name,
    enabled: true,
    process_name: preset.process_name,
    cmdline_pattern: preset.cmdline_pattern ?? '',
    image_path_pattern: preset.image_path_pattern ?? '',
    package_family_name: preset.package_family_name ?? '',
    hack_tree: true,
    protocol: preset.protocol,
    proxy_group_id: g?.id ?? 0,
    proxy: {
      type: g?.type ?? 'socks5',
      host: g?.host ?? '127.0.0.1',
      port: g?.port ?? 7890,
    },
    dst_filter: {
      include_cidrs: [],
      exclude_cidrs: [],
      include_ports: [],
      exclude_ports: [],
    },
  }
}

export function isPresetInstalled(preset: AppPreset, rules: AutoRule[]): boolean {
  const pProc = preset.process_name.toLowerCase()
  const pPkg = (preset.package_family_name ?? '').toLowerCase()
  const pCmd = (preset.cmdline_pattern ?? '').toLowerCase()
  return rules.some(r =>
    r.process_name.toLowerCase() === pProc
    && (r.package_family_name ?? '').toLowerCase() === pPkg
    && r.cmdline_pattern.toLowerCase() === pCmd,
  )
}

/**
 * Build a RulePrefill from a live process or a network activity row.
 * For Microsoft Store apps, prefers stable `package_family_name` over the
 * versioned `WindowsApps\...` directory so Store updates do not break the rule.
 */
export function processToPrefill(
  name: string,
  detail?: Pick<ProcessInfo, 'image_path' | 'cmdline' | 'package_family_name'> | null,
  protocol: RuleProtocol = 'tcp',
): RulePrefill {
  const pfn = detail?.package_family_name?.trim() ?? ''
  const workDir = pfn ? '' : dirOf(detail?.image_path || exeFromCmdline(detail?.cmdline ?? ''))
  return {
    name: name ? `${name} 的规则` : '',
    processName: name,
    workDir,
    packageFamilyName: pfn,
    protocol,
  }
}

/** Build a RulePrefill from a NetworkConnection decision row. */
export function connectionToPrefill(
  conn: Pick<NetworkConnection, 'process_name' | 'protocol'>,
  detail?: Pick<ProcessInfo, 'image_path' | 'cmdline' | 'package_family_name'> | null,
): RulePrefill {
  const proto: RuleProtocol = conn.protocol === 'UDP' ? 'udp' : 'tcp'
  return processToPrefill(conn.process_name, detail, proto)
}
