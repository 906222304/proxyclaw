<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { getLog, revealFile, type LogSnapshot } from '@/api/client'

const open = ref(false)
const automatic = ref(true)
const busy = ref(false)
const error = ref('')
const actionMessage = ref('')
const query = ref('')
const level = ref('all')
const updatedAt = ref('')
const snapshot = ref<LogSnapshot | null>(null)
const logPane = ref<HTMLPreElement | null>(null)
const follow = ref(true)
let generation = 0
let controller: AbortController | null = null
let timer: ReturnType<typeof setTimeout> | null = null

const filtered = computed(() => {
  const needle = query.value.trim().toLocaleLowerCase()
  return (snapshot.value?.text ?? '').split('\n').filter(line => {
    if (needle && !line.toLocaleLowerCase().includes(needle)) return false
    return level.value === 'all' || /^\S+\s+\S+\s+\[(W|E|C|WARN|WARNING|ERROR|CRITICAL)\]/.test(line)
  }).join('\n')
})

function stop() {
  ++generation
  if (timer !== null) clearTimeout(timer)
  timer = null
  controller?.abort()
  controller = null
  busy.value = false
}

async function load() {
  if (!open.value || document.hidden || busy.value) return
  const current = ++generation
  const request = new AbortController()
  controller = request
  busy.value = true
  try {
    const data = await getLog(request.signal)
    if (current !== generation || request.signal.aborted) return
    snapshot.value = data
    error.value = ''
    updatedAt.value = new Date().toLocaleTimeString('zh-CN')
    await nextTick()
    if (follow.value && logPane.value) logPane.value.scrollTop = logPane.value.scrollHeight
  } catch (err) {
    if (current === generation && !request.signal.aborted)
      error.value = err instanceof Error ? err.message : '日志读取失败，请稍后重试。'
  } finally {
    if (current === generation) {
      busy.value = false
      controller = null
      if (open.value && automatic.value && !document.hidden)
        timer = setTimeout(() => { timer = null; void load() }, 3000)
    }
  }
}

function refresh() {
  stop()
  if (open.value && !document.hidden) void load()
}

function onScroll() {
  const pane = logPane.value
  if (pane) follow.value = pane.scrollHeight - pane.scrollTop - pane.clientHeight < 32
}

async function copy() {
  try {
    await navigator.clipboard.writeText(filtered.value)
    actionMessage.value = '已复制当前显示的日志'
  } catch {
    actionMessage.value = '复制失败，请选中日志后按 Ctrl+C。'
  }
}

async function reveal() {
  if (!snapshot.value) return
  try {
    await revealFile(snapshot.value.path)
    actionMessage.value = ''
  } catch {
    actionMessage.value = '打开文件位置失败，请稍后重试。'
  }
}

watch([open, automatic], () => {
  actionMessage.value = ''
  refresh()
})
onMounted(() => document.addEventListener('visibilitychange', refresh))
onUnmounted(() => {
  stop()
  document.removeEventListener('visibilitychange', refresh)
})
</script>

<template>
  <Button size="sm" variant="outline" class="shrink-0" @click="open = true">查看日志</Button>
  <Dialog v-model:open="open">
    <DialogContent class="flex flex-col h-[80vh] sm:max-w-5xl p-4 gap-3">
      <DialogHeader class="pr-6">
        <DialogTitle>运行日志</DialogTitle>
        <DialogDescription>查看最近的连接与错误记录，自动刷新间隔为 3 秒。</DialogDescription>
      </DialogHeader>
      <div class="flex flex-wrap items-center gap-2">
        <input v-model="query" type="search" placeholder="搜索日志…" aria-label="搜索日志"
               class="h-8 min-w-32 flex-1 rounded border px-2 text-sm bg-background" />
        <select v-model="level" aria-label="日志筛选" class="h-8 rounded border px-2 text-sm bg-background">
          <option value="all">全部日志</option>
          <option value="problems">警告和错误</option>
        </select>
        <label class="flex items-center gap-1.5 text-xs whitespace-nowrap">
          <input v-model="automatic" type="checkbox" />自动刷新
        </label>
        <Button size="sm" variant="outline" :disabled="busy" @click="refresh">刷新</Button>
        <Button size="sm" variant="outline" :disabled="!filtered" @click="copy">复制日志</Button>
      </div>
      <p v-if="error" role="alert" class="text-xs text-red-600 dark:text-red-400">{{ error }}</p>
      <pre ref="logPane" tabindex="0" aria-label="日志内容" @scroll="onScroll"
           class="flex-1 min-h-0 overflow-auto rounded border bg-slate-50 dark:bg-[#101922] p-3 text-xs leading-5 font-mono whitespace-pre-wrap break-all text-slate-700 dark:text-slate-200">{{ filtered || (busy ? '正在读取日志…' : snapshot && !snapshot.exists ? '日志文件尚未生成。' : snapshot?.text ? '没有匹配的日志。' : '暂无日志记录。') }}</pre>
      <div class="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
        <span>{{ snapshot?.truncated ? '显示最新片段，完整记录请打开文件位置查看。' : '最多显示最近 1000 行。' }}<span v-if="updatedAt"> 更新于 {{ updatedAt }}</span></span>
        <Button size="sm" variant="outline" :disabled="!snapshot" @click="reveal">打开文件位置</Button>
      </div>
      <p v-if="snapshot" class="text-xs break-all text-slate-500 dark:text-slate-400">{{ snapshot.path }}</p>
      <p v-if="actionMessage" role="status" class="text-xs text-slate-600 dark:text-slate-300">{{ actionMessage }}</p>
    </DialogContent>
  </Dialog>
</template>
