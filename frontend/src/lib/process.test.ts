import { describe, expect, it } from 'vitest'
import type { ProcessInfo } from '@/api/types'
import { countProcesses, dirOf, exeFromCmdline, filterTree, flattenTree, matchedPids, subtreeActive } from './process'

const p = (pid: number, name: string, children: ProcessInfo[] = [], hijacked = false): ProcessInfo =>
  ({ pid, parent_pid: 0, name, hijacked, children })

const tree = [
  p(1, 'explorer.exe', [
    p(2, 'antigravity.exe', [p(3, 'chrome.exe'), p(4, 'cmd.exe', [], true)]),
    p(5, 'notepad.exe'),
  ]),
  p(6, 'svchost.exe'),
]

describe('process tree helpers', () => {
  it('counts every node', () => {
    expect(countProcesses(tree)).toBe(6)
  })

  it('keeps a match with its subtree and only the ancestor path', () => {
    const out = filterTree(tree, 'antigravity', 'all')
    expect(out).toHaveLength(1)
    expect(out[0]!.children!.map(c => c.pid)).toEqual([2])
    expect(out[0]!.children![0]!.children!.map(c => c.pid)).toEqual([3, 4])
    expect(matchedPids(tree, 'antigravity', 'all')).toEqual(new Set([2]))
  })

  it('filters by proxy state', () => {
    const out = filterTree(tree, '', 'proxied')
    expect(out[0]!.children![0]!.children!.map(c => c.pid)).toEqual([4])
    expect(filterTree(tree, '', 'all')).toBe(tree)
  })

  it('propagates activity to ancestors', () => {
    expect(subtreeActive(tree, pid => pid === 3)).toEqual(new Set([3, 2, 1]))
  })

  it('flattens only expanded nodes with guide-line rails', () => {
    const rows = flattenTree(tree, pid => pid === 1 || pid === 2)
    expect(rows.map(r => r.node.pid)).toEqual([1, 2, 3, 4, 5, 6])
    const r3 = rows[2]!
    expect(r3.depth).toBe(2)
    // Its parent (2) has a next sibling (5): the level-1 rail continues.
    expect(r3.rails).toEqual([5])
    expect(r3.nextSibling).toBe(4)
    expect(rows[3]!.nextSibling).toBeNull()
    expect(rows[4]!.rails).toEqual([])
    expect(flattenTree(tree, () => false).map(r => r.node.pid)).toEqual([1, 6])
  })

  it('parses executable paths', () => {
    expect(exeFromCmdline('"C:\\Program Files\\A\\a.exe" --x')).toBe('C:\\Program Files\\A\\a.exe')
    expect(exeFromCmdline('C:\\b.exe -y')).toBe('C:\\b.exe')
    expect(dirOf('C:\\Program Files\\A\\a.exe')).toBe('C:\\Program Files\\A\\')
    expect(dirOf('a.exe')).toBe('')
  })
})
