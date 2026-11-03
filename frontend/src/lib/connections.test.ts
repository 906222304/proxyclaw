import { describe, expect, it } from 'vitest'
import type { NetworkConnection } from '@/api/types'
import { columnsFor, filterRows, nextSort, rowId, sortRows } from './connections'

function conn(p: Partial<NetworkConnection>): NetworkConnection {
  return {
    pid: 1, local_ip: '127.0.0.1', local_port: 1000, remote_ip: '1.1.1.1', remote_port: 443,
    state: 'ESTABLISHED', dest: '', hijacked: false, pid_alive: true, proxy_status: 'DIRECT',
    process_name: 'a.exe', protocol: 'TCP', ...p,
  }
}

const rows = [
  conn({ pid: 30, process_name: 'chrome.exe', remote_ip: '10.0.0.2', local_port: 900, proxy_status: 'PROXIED' }),
  conn({ pid: 4, process_name: 'Code.exe', remote_ip: '10.0.0.10', local_port: 80, state: 'TIME_WAIT', protocol: 'UDP' }),
  conn({ pid: 200, process_name: 'curl.exe', remote_ip: '', remote_port: 0, local_port: 5000, state: 'BOUND', proxy_status: 'IGNORED' }),
]

describe('sorting', () => {
  it('cycles asc → desc → none per column and restarts on a new column', () => {
    let s = nextSort(null, 'pid')
    expect(s).toEqual({ key: 'pid', dir: 'asc' })
    s = nextSort(s, 'pid')
    expect(s).toEqual({ key: 'pid', dir: 'desc' })
    expect(nextSort(s, 'pid')).toBeNull()
    expect(nextSort(s, 'state')).toEqual({ key: 'state', dir: 'asc' })
  })

  it('sorts numbers numerically and strings naturally, case-insensitive', () => {
    expect(sortRows(rows, { key: 'pid', dir: 'asc' }).map(r => r.pid)).toEqual([4, 30, 200])
    expect(sortRows(rows, { key: 'local_port', dir: 'desc' }).map(r => r.local_port)).toEqual([5000, 900, 80])
    expect(sortRows(rows, { key: 'process_name', dir: 'asc' }).map(r => r.process_name)).toEqual(['chrome.exe', 'Code.exe', 'curl.exe'])
    expect(sortRows(rows, { key: 'remote', dir: 'asc' }).map(r => r.remote_ip)).toEqual(['', '10.0.0.2', '10.0.0.10'])
  })

  it('returns input order when unsorted and is stable', () => {
    expect(sortRows(rows, null)).toBe(rows)
    const same = [conn({ pid: 1, local_port: 1 }), conn({ pid: 1, local_port: 2 })]
    expect(sortRows(same, { key: 'pid', dir: 'desc' }).map(r => r.local_port)).toEqual([1, 2])
  })
})

describe('quick filter', () => {
  it('matches raw values and Chinese labels, all words required', () => {
    expect(filterRows(rows, '').length).toBe(3)
    expect(filterRows(rows, 'CHROME').map(r => r.pid)).toEqual([30])
    expect(filterRows(rows, '10.0.0.1').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, '等待超时').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, 'time_wait').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, '已忽略').map(r => r.pid)).toEqual([200])
    expect(filterRows(rows, 'udp code').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, 'udp chrome')).toEqual([])
  })
})

describe('row identity and columns', () => {
  it('keeps dual-stack sockets apart', () => {
    expect(rowId(conn({ local_ip: '0.0.0.0' }))).not.toBe(rowId(conn({ local_ip: '::' })))
  })
  it('shows the process column only in the all-processes view', () => {
    expect(columnsFor(true).map(c => c.key)[0]).toBe('process_name')
    expect(columnsFor(false).map(c => c.key)).not.toContain('process_name')
  })
})
