import type { ProcessInfo } from '@/api/types'

export type ProcessFilter = 'all' | 'proxied' | 'direct'

export function countProcesses(nodes: ProcessInfo[]): number {
  let n = 0
  for (const node of nodes) n += 1 + (node.children ? countProcesses(node.children) : 0)
  return n
}

export function findInTree(nodes: ProcessInfo[], pid: number): ProcessInfo | null {
  for (const n of nodes) {
    if (n.pid === pid) return n
    if (n.children) {
      const f = findInTree(n.children, pid)
      if (f) return f
    }
  }
  return null
}

export function matchesSearch(node: ProcessInfo, query: string): boolean {
  const q = query.toLowerCase()
  return (
    node.name.toLowerCase().includes(q)
    || String(node.pid).includes(q)
    || (node.cmdline?.toLowerCase().includes(q) ?? false)
  )
}

export function matchesFilter(node: ProcessInfo, filter: ProcessFilter): boolean {
  if (filter === 'all') return true
  if (filter === 'proxied') return node.hijacked
  return !node.hijacked
}

/**
 * Keep matching nodes with their whole subtree (so the user sees descendant
 * context), and keep non-matching ancestors only on the path to a match.
 */
export function filterTree(nodes: ProcessInfo[], query: string, filter: ProcessFilter): ProcessInfo[] {
  const q = query.trim()
  if (!q && filter === 'all') return nodes
  const out: ProcessInfo[] = []
  for (const node of nodes) {
    if ((!q || matchesSearch(node, q)) && matchesFilter(node, filter)) {
      out.push(node)
    } else {
      const kids = node.children ? filterTree(node.children, q, filter) : []
      if (kids.length > 0) out.push({ ...node, children: kids })
    }
  }
  return out
}

/** PIDs whose own data matches the query (amber Ctrl+F style highlight). */
export function matchedPids(nodes: ProcessInfo[], query: string, filter: ProcessFilter): Set<number> {
  const set = new Set<number>()
  const q = query.trim()
  if (!q) return set
  const walk = (n: ProcessInfo) => {
    if (matchesSearch(n, q) && matchesFilter(n, filter)) set.add(n.pid)
    n.children?.forEach(walk)
  }
  nodes.forEach(walk)
  return set
}

/** PIDs whose subtree (self or any descendant) is active. */
export function subtreeActive(nodes: ProcessInfo[], isActive: (pid: number) => boolean): Set<number> {
  const set = new Set<number>()
  const walk = (n: ProcessInfo): boolean => {
    let any = isActive(n.pid)
    for (const c of n.children ?? []) if (walk(c)) any = true
    if (any) set.add(n.pid)
    return any
  }
  nodes.forEach(walk)
  return set
}

export interface FlatRow {
  node: ProcessInfo
  depth: number
  hasChildren: boolean
  expanded: boolean
  /**
   * Guide-line columns for depths 0..depth-1: for each ancestor level, the
   * PID of the next sibling below at that level (vertical line continues,
   * coloured by that sibling's subtree), or null (no line).
   */
  rails: (number | null)[]
  /** PID of the next sibling (bottom half of this row's elbow), or null if last. */
  nextSibling: number | null
}

/** Flatten the visible part of the tree for virtualised rendering. */
export function flattenTree(nodes: ProcessInfo[], isExpanded: (pid: number) => boolean): FlatRow[] {
  const rows: FlatRow[] = []
  const walk = (list: ProcessInfo[], depth: number, rails: (number | null)[]) => {
    list.forEach((node, i) => {
      const hasChildren = !!node.children?.length
      const expanded = hasChildren && isExpanded(node.pid)
      const nextSibling = list[i + 1]?.pid ?? null
      rows.push({ node, depth, hasChildren, expanded, rails, nextSibling })
      if (expanded) walk(node.children!, depth + 1, depth === 0 ? [] : [...rails, nextSibling])
    })
  }
  walk(nodes, 0, [])
  return rows
}

/** Executable path from a command line (quoted or first token). */
export function exeFromCmdline(cmd: string): string {
  if (cmd.startsWith('"')) {
    const end = cmd.indexOf('"', 1)
    return end > 0 ? cmd.slice(1, end) : ''
  }
  const space = cmd.indexOf(' ')
  return space > 0 ? cmd.slice(0, space) : cmd
}

/** Directory (with trailing separator) of a path, or ''. */
export function dirOf(path: string): string {
  const sep = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  return sep > 0 ? path.slice(0, sep + 1) : ''
}
