<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted, computed, useId, nextTick } from 'vue'
import type * as Monaco from 'monaco-editor/esm/vs/editor/editor.api.js'

import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { getConfig, updateConfig, getAutostart, setAutostart } from '@/api/client'
import { Save } from 'lucide-vue-next'
import { useTheme } from '@/composables/useTheme'
import { useStatusBus } from '@/composables/useStatusBus'
import { PROXYCLAW_VERSION } from '@/version'

const { isDark } = useTheme()
const { pushError } = useStatusBus()

const editorContainer = ref<HTMLDivElement | null>(null)
let editor: Monaco.editor.IStandaloneCodeEditor | null = null
let monaco: typeof Monaco | null = null
let editorGeneration = 0
const editorLoading = ref(false)
const editorError = ref<string | null>(null)

const savedContent = ref('')
const currentContent = ref('')
const saving = ref(false)
const saveMessage = ref<{ type: 'success' | 'error'; text: string } | null>(null)
const closeToTray = ref(true)
const closeToTraySaving = ref(false)
const editorOpen = ref(false)

// Autostart (Windows Task Scheduler entry; not persisted in proxyclaw.json)
const autostartEnabled = ref(false)
const autostartMinimized = ref(false)
const autostartMessage = ref<string | null>(null)

// DNS settings
const dnsEnabled = ref(false)
const dnsMode = ref('forwarder')
const dnsUpstream = ref('')
const dnsSaveMessage = ref<string | null>(null)

// Log level — quill switches at runtime via clew::set_log_level (wired in
// app.cpp's config_store observer chain). Changing this dropdown reloads
// the live process; no restart needed.
const logLevel = ref('info')
const logLevelMessage = ref<string | null>(null)

// a11y: unique ids for label/field association
const dnsModeId = useId()
const dnsUpstreamId = useId()
const logLevelId = useId()

const hasUnsavedChanges = computed(() => {
  return currentContent.value !== savedContent.value
})

async function fetchConfig(options: { pushToEditor?: boolean; generation?: number } = {}) {
  try {
    const config = await getConfig()
    if (options.generation != null && options.generation !== editorGeneration) return false
    const json = JSON.stringify(config, null, 2)
    const ui = (config as Record<string, unknown>).ui as Record<string, unknown> | undefined
    closeToTray.value = (ui?.close_to_tray as boolean | undefined) ?? true
    const dns = (config as Record<string, unknown>).dns as Record<string, unknown> | undefined
    if (dns) {
      dnsEnabled.value = !!dns.enabled
      dnsMode.value = (dns.mode as string) || 'forwarder'
      dnsUpstream.value = (dns.upstream_host as string) || ''
    }
    const lvl = (config as Record<string, unknown>).log_level as string | undefined
    if (lvl) logLevel.value = lvl
    // Only overwrite the Monaco editor when explicitly requested (initial open),
    // OR when there are no unsaved local edits. Otherwise preserve user's work.
    const shouldPush = options.pushToEditor === true
      || (editor !== null && !hasUnsavedChanges.value)
    if (shouldPush) {
      savedContent.value = json
      currentContent.value = json
      if (editor) editor.setValue(json)
    }
    return true
  } catch {
    // Backend not available
    return false
  }
}

async function saveLogLevel() {
  logLevelMessage.value = null
  try {
    const config = await getConfig() as Record<string, unknown>
    config.log_level = logLevel.value
    await updateConfig(config)
    logLevelMessage.value = '已保存'
    setTimeout(() => { logLevelMessage.value = null }, 2000)
    await fetchConfig()
  } catch {
    logLevelMessage.value = '保存失败'
  }
}

async function saveDns() {
  dnsSaveMessage.value = null
  try {
    const config = await getConfig() as Record<string, unknown>
    const dns = (config.dns || {}) as Record<string, unknown>
    dns.enabled = dnsEnabled.value
    dns.mode = dnsMode.value
    dns.upstream_host = dnsUpstream.value
    dns.upstream_port = 53
    if (!dns.listen_host) dns.listen_host = '127.0.0.2'
    if (!dns.listen_port) dns.listen_port = 53
    config.dns = dns
    await updateConfig(config)
    dnsSaveMessage.value = '已保存'
    setTimeout(() => { dnsSaveMessage.value = null }, 2000)
    await fetchConfig()  // refresh local state only; preserves unsaved Monaco edits
  } catch {
    dnsSaveMessage.value = '保存失败'
  }
}

async function saveConfig() {
  if (!editor) return
  saving.value = true
  saveMessage.value = null
  try {
    const content = editor.getValue()
    const parsed = JSON.parse(content) as Record<string, unknown>
    await updateConfig(parsed)
    savedContent.value = content
    currentContent.value = content
    await fetchConfig()
    saveMessage.value = { type: 'success', text: '配置已保存并重新加载' }
    setTimeout(() => {
      saveMessage.value = null
    }, 3000)
  } catch (err) {
    let message: string
    if (err instanceof SyntaxError) message = 'JSON 格式无效'
    else if (err instanceof Error) message = err.message
    else message = '保存配置失败'
    saveMessage.value = { type: 'error', text: message }
  } finally {
    saving.value = false
  }
}

async function fetchAutostart() {
  try {
    const s = await getAutostart()
    autostartEnabled.value = s.enabled
    autostartMinimized.value = s.start_minimized
  } catch {
    // Backend not available; leave defaults (both false).
  }
}

async function applyAutostart(next: { enabled: boolean; start_minimized: boolean }) {
  autostartMessage.value = null
  // Optimistic update so the toggle feels immediate; revert on failure.
  const prev = { enabled: autostartEnabled.value, start_minimized: autostartMinimized.value }
  autostartEnabled.value = next.enabled
  autostartMinimized.value = next.start_minimized
  try {
    const result = await setAutostart(next)
    autostartEnabled.value = result.enabled
    autostartMinimized.value = result.start_minimized
  } catch (err) {
    autostartEnabled.value = prev.enabled
    autostartMinimized.value = prev.start_minimized
    autostartMessage.value = err instanceof Error ? err.message : '更新开机启动设置失败'
    setTimeout(() => { autostartMessage.value = null }, 4000)
  }
}

async function toggleAutostart() {
  await applyAutostart({
    enabled: !autostartEnabled.value,
    start_minimized: autostartMinimized.value,
  })
}

async function toggleStartMinimized() {
  if (!autostartEnabled.value) return
  await applyAutostart({
    enabled: true,
    start_minimized: !autostartMinimized.value,
  })
}

async function toggleCloseToTray() {
  if (closeToTraySaving.value) return
  closeToTraySaving.value = true
  const next = !closeToTray.value
  try {
    const config = await getConfig() as Record<string, unknown>
    const ui = (config.ui || {}) as Record<string, unknown>
    ui.close_to_tray = next
    config.ui = ui
    await updateConfig(config)
    closeToTray.value = next
    // Refresh Monaco editor content
    await fetchConfig()
  } catch (err) {
    pushError(err, '更新后台运行设置失败')
  } finally {
    closeToTraySaving.value = false
  }
}

function initEditor() {
  if (!editorContainer.value || editor || !monaco) return
  editor = monaco.editor.create(editorContainer.value, {
    value: currentContent.value,
    language: 'json',
    theme: isDark.value ? 'vs-dark' : 'vs',
    automaticLayout: true,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    fontSize: 13,
    lineNumbers: 'on',
    tabSize: 2,
    wordWrap: 'on',
    renderLineHighlight: 'line',
    // JSON configuration needs syntax/validation, not background symbol searches.
    occurrencesHighlight: 'off',
    padding: { top: 8, bottom: 8 },
  })

  editor.onDidChangeModelContent(() => {
    if (editor) {
      currentContent.value = editor.getValue()
    }
  })

  editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
    saveConfig()
  })
}

async function openEditor() {
  const generation = ++editorGeneration
  editorOpen.value = true
  editorLoading.value = true
  editorError.value = null
  try {
    const [loaded, runtime] = await Promise.all([
      fetchConfig({ pushToEditor: true, generation }),
      import('@/lib/monacoRuntime'),
    ])
    if (generation !== editorGeneration || !editorOpen.value) return
    if (!loaded) throw new Error('读取配置失败，请重试')
    monaco = runtime.monaco
    await nextTick()
    if (generation === editorGeneration && editorOpen.value) initEditor()
  } catch (err) {
    if (generation === editorGeneration) {
      editorError.value = err instanceof Error ? err.message : '加载配置编辑器失败'
    }
  } finally {
    if (generation === editorGeneration) editorLoading.value = false
  }
}

function disposeEditor() {
  // Disposing the view does not release its text model. Release both so
  // repeated opens don't retain old JSON and language-worker models.
  const model = editor?.getModel()
  editor?.dispose()
  model?.dispose()
  editor = null
}

function closeEditor() {
  if (hasUnsavedChanges.value) {
    if (!confirm('有尚未保存的修改，确定放弃吗？')) return
  }
  ++editorGeneration
  editorOpen.value = false
  editorLoading.value = false
  disposeEditor()
}

onMounted(() => {
  // Only fetch close-to-tray + autostart state, don't init editor
  fetchConfig()
  fetchAutostart()
})

watch(isDark, (dark) => {
  if (editor && monaco) {
    monaco.editor.setTheme(dark ? 'vs-dark' : 'vs')
  }
})

onUnmounted(() => {
  ++editorGeneration
  disposeEditor()
})
</script>

<template>
  <div class="flex flex-col h-full overflow-auto thin-scrollbar">
    <div class="p-6 flex flex-col gap-6 flex-1 min-h-0">
      <!-- General Section -->
      <div class="max-w-xl">
        <h2 class="text-base font-semibold text-slate-800 dark:text-slate-100 mb-1">通用设置</h2>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">设置 ProxyClaw 的运行方式。</p>
        <div class="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden divide-y divide-slate-200 dark:divide-slate-800">
          <div class="flex items-center justify-between px-4 py-3 bg-white dark:bg-[#18181b]">
            <div>
              <p class="text-sm font-medium text-slate-700 dark:text-slate-200">关闭窗口后保持后台运行</p>
              <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                默认开启，关闭窗口后代理继续运行。点击托盘图标重新打开，右键选择“退出 ProxyClaw”结束运行。设置立即生效。
              </p>
            </div>
            <button
              class="relative shrink-0 ml-4 inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-[#18181b]"
              :class="closeToTray ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-600'"
              role="switch"
              aria-label="关闭窗口后保持后台运行"
              :aria-checked="closeToTray"
              :disabled="closeToTraySaving"
              @click="toggleCloseToTray"
            >
              <span
                class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"
                :class="closeToTray ? 'translate-x-[18px]' : 'translate-x-0.5'"
              />
            </button>
          </div>

          <!-- Autostart on Logon -->
          <div class="px-4 py-3 bg-white dark:bg-[#18181b]">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-slate-700 dark:text-slate-200">登录 Windows 后自动启动</p>
                <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  以管理员权限启动，无需每次登录时确认。移动 proxyclaw.exe 后，请重新开启此选项。
                </p>
              </div>
              <button
                class="relative shrink-0 ml-4 inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-[#18181b]"
                :class="autostartEnabled ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-600'"
                role="switch"
                aria-label="登录 Windows 后自动启动"
                :aria-checked="autostartEnabled"
                @click="toggleAutostart"
              >
                <span
                  class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"
                  :class="autostartEnabled ? 'translate-x-[18px]' : 'translate-x-0.5'"
                />
              </button>
            </div>

            <div class="mt-3 pl-4 flex items-center justify-between"
                 :class="autostartEnabled ? '' : 'opacity-50'">
              <div>
                <p class="text-xs font-medium text-slate-700 dark:text-slate-200">启动时隐藏到托盘</p>
                <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  自动启动时仅显示托盘图标；开启“登录 Windows 后自动启动”后生效。
                </p>
              </div>
              <button
                :disabled="!autostartEnabled"
                role="switch"
                aria-label="启动时隐藏到托盘"
                :aria-checked="autostartMinimized"
                class="relative shrink-0 ml-4 inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-[#18181b] disabled:cursor-not-allowed"
                :class="autostartMinimized ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-600'"
                @click="toggleStartMinimized"
              >
                <span
                  class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"
                  :class="autostartMinimized ? 'translate-x-[18px]' : 'translate-x-0.5'"
                />
              </button>
            </div>
            <p v-if="autostartMessage" class="mt-2 text-xs text-red-500">{{ autostartMessage }}</p>
          </div>

          <!-- DNS Proxy -->
          <div class="px-4 py-3 bg-white dark:bg-[#18181b]">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-slate-700 dark:text-slate-200">DNS 代理</p>
                <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  通过代理转发 DNS 查询，适用于系统 DNS 无法解析目标服务的情况。此模式会修改系统 DNS，影响整台电脑。
                </p>
              </div>
              <button
                class="relative shrink-0 ml-4 inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-[#18181b]"
                :class="dnsEnabled ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-600'"
                role="switch"
                aria-label="DNS 代理"
                :aria-checked="dnsEnabled"
                @click="dnsEnabled = !dnsEnabled; saveDns()"
              >
                <span
                  class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"
                  :class="dnsEnabled ? 'translate-x-[18px]' : 'translate-x-0.5'"
                />
              </button>
            </div>

            <div v-if="dnsEnabled" class="mt-3 pl-0 space-y-3">
              <div class="flex items-center gap-3">
                <Label :for="dnsModeId" class="text-xs text-slate-500 dark:text-slate-400 w-20 shrink-0">模式</Label>
                <select
                  :id="dnsModeId"
                  v-model="dnsMode"
                  @change="saveDns"
                  class="h-8 px-2 text-sm border border-slate-200 dark:border-slate-700 rounded bg-slate-50 dark:bg-[#101922] text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="forwarder">全局转发（系统 DNS → 127.0.0.2）</option>
                </select>
              </div>
              <div class="flex items-center gap-3">
                <Label :for="dnsUpstreamId" class="text-xs text-slate-500 dark:text-slate-400 w-20 shrink-0">上游服务器</Label>
                <input
                  :id="dnsUpstreamId"
                  v-model="dnsUpstream"
                  @change="saveDns"
                  type="text"
                  placeholder="DNS 服务器地址"
                  class="h-8 px-2 text-sm font-mono border border-slate-200 dark:border-slate-700 rounded bg-slate-50 dark:bg-[#101922] text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500 w-40"
                />
                <span class="text-xs text-slate-500 dark:text-slate-400 font-mono">:53</span>
              </div>
              <p v-if="dnsSaveMessage" class="text-xs text-green-500">{{ dnsSaveMessage }}</p>
            </div>
          </div>

          <!-- Log Level -->
          <div class="px-4 py-3 bg-white dark:bg-[#18181b]">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-slate-700 dark:text-slate-200">日志级别</p>
                <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  设置日志详细程度，修改后立即生效。
                  <code class="font-mono">debug</code> 模式将详细诊断记录写入 <code class="font-mono">proxyclaw.log</code>.
                </p>
              </div>
              <div class="flex items-center gap-2 ml-4 shrink-0">
                <Label :for="logLevelId" class="sr-only">日志级别</Label>
                <select
                  :id="logLevelId"
                  v-model="logLevel"
                  @change="saveLogLevel"
                  class="h-8 px-2 text-sm border border-slate-200 dark:border-slate-700 rounded bg-slate-50 dark:bg-[#101922] text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="debug">调试</option>
                  <option value="info">信息</option>
                  <option value="warning">警告</option>
                  <option value="error">错误</option>
                </select>
                <span v-if="logLevelMessage" class="text-xs text-green-500">{{ logLevelMessage }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Configuration File Section -->
      <div
        class="flex flex-col"
        :class="editorOpen ? 'flex-1 min-h-[360px]' : 'max-w-xl shrink-0'"
      >
        <div v-if="!editorOpen" class="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">
          <div class="flex items-center justify-between px-4 py-3 bg-white dark:bg-[#18181b]">
            <div>
              <p class="text-sm font-medium text-slate-700 dark:text-slate-200">配置文件</p>
              <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">直接编辑 JSON 配置，进行高级设置。</p>
            </div>
            <Button size="sm" variant="outline" @click="openEditor">
              编辑
            </Button>
          </div>
        </div>

        <template v-else>
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <h2 class="text-base font-semibold text-slate-800 dark:text-slate-100">配置文件</h2>
              <Badge
                v-if="hasUnsavedChanges"
                variant="outline"
                class="text-orange-400 border-orange-400/40"
              >
                尚未保存
              </Badge>
              <span
                v-if="saveMessage"
                class="text-xs"
                :class="saveMessage.type === 'success' ? 'text-green-500' : 'text-red-500'"
              >
                {{ saveMessage.text }}
              </span>
            </div>
            <div class="flex items-center gap-2">
              <Button
                size="sm"
                :disabled="saving || editorLoading || editorError !== null || !hasUnsavedChanges"
                @click="saveConfig"
              >
                <Save class="size-4 mr-1" />
                {{ saving ? '正在保存…' : '保存并重新加载' }}
              </Button>
              <Button size="sm" variant="outline" @click="closeEditor">
                关闭
              </Button>
            </div>
          </div>

          <!-- Monaco Editor -->
          <p v-if="editorLoading" role="status" class="text-sm text-slate-500">正在加载配置编辑器…</p>
          <div v-if="editorError" role="alert" class="flex items-center gap-3 text-sm text-red-500">
            {{ editorError }}
            <Button size="sm" variant="outline" @click="openEditor">重试</Button>
          </div>
          <div
            ref="editorContainer"
            class="flex-1 min-h-[300px] rounded-md border border-slate-200 dark:border-slate-800 overflow-hidden"
          />
        </template>
      </div>

      <!-- About Section -->
      <div class="max-w-xl">
        <h2 class="text-base font-semibold text-slate-800 dark:text-slate-100 mb-1">关于</h2>
        <div class="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">
          <div class="px-4 py-3 bg-white dark:bg-[#18181b] space-y-1">
            <p class="text-xs text-slate-500 dark:text-slate-400">
              ProxyClaw <span class="font-mono text-slate-700 dark:text-slate-300">v{{ PROXYCLAW_VERSION }}</span>
            </p>
            <p class="text-xs text-slate-500 dark:text-slate-400">
              Windows 进程级代理与分流 · 基于 Clew ·
              <a href="https://github.com/ymonster/clew-proxy" target="_blank"
                 class="text-blue-600 dark:text-blue-400 hover:underline">上游源码</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
