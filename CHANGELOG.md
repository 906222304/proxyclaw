# Changelog

## Unreleased

### Added

- IPv6 block for proxied processes (`ipv6.mode`, default `block`; Settings →
  Network → IPv6). ProxyClaw does not proxy IPv6, so a proxied process that
  reached a dual-stack host over IPv6 used to leave direct, past the proxy.
  Now its IPv6 TCP connect is refused at once (a new WinDivert handle diverts
  only outbound IPv6 SYNs; the SOCKET layer's verdict is applied per port,
  undecided SYNs wait up to 20 ms, a blocked SYN is answered with an inbound
  RST) and its IPv6 UDP datagrams are dropped, so applications fall back to
  IPv4 and go through the proxy. Local-scope IPv6 (link-local, unique local,
  multicast), destination ports the rule excludes, and rules whose include
  CIDRs (IPv4 only) cannot cover IPv6 are not blocked. `direct` keeps the old
  behaviour. Changes apply at runtime.
- Decision reason `ipv6_blocked`; `/api/stats` adds `ipv6_blocked {tcp, udp}`
  (TCP connects refused, UDP datagrams dropped) and `ipv6 {mode, syn_*}`.

### Changed

- The UDP NETWORK handle now diverts IPv6 UDP as well (passed through
  unchanged unless blocked).
- IPv6 decision records name why a connection was not blocked
  (`not-proxied`, `self`, a route reason, or `ipv6` in direct mode).

## v0.14.0 (2026-11-09)

### Changed

- Per-connection decision record: the TCP and UDP decision paths record each
  verdict at CONNECT / BIND time (pid + psn, proxied / direct, reason, rule
  id, source rule / tree / manual, proxy group, config version, timestamp) in
  a bounded lock-free ring with a per-port index (`core/decision_log.hpp`;
  O(1), allocation-free on the hot path). The watchdog, a full SYN pool and
  IPv6 connections are recorded too (`watchdog`, `pool_exhausted`, `ipv6`),
  as is a decision rejected as `late`.
- `/api/tcp` and `/api/udp` no longer recompute "proxied" against the current
  rules on every poll: `proxy_status` and `route_reason` come from the
  recorded decision, and each row carries `decision {verdict, reason,
  rule_id, source, group, config_version, at_ms, pid, psn}` plus
  `decision_source` (`recorded`, `recomputed` for rows without a record —
  connections older than ProxyClaw or evicted from the log — or `none` for
  listening sockets). Changing or deleting a rule no longer changes what an
  established connection shows. A proxied connection whose rule was removed
  stays `PROXIED`; a direct row with a recorded `late` / `watchdog` reason
  shows `IGNORED` (with that `route_reason`) instead of `PROXIED`.
- `/api/stats` adds `config_version` and `decisions {written, dropped,
  capacity}`.
- Connection JSON is built off the process-tree strand (ROADMAP v0.14 #3).
  The strand query now only copies per-row facts (pid alive, proxied, process
  name, the record's rule id, and — for rows without a record whose process
  is proxied — the current-rules fallback verdict); OS table reads,
  UdpSessionTable / DecisionLog lookups, string formatting and all
  `nlohmann::json` building run on the HTTP thread
  (`projection/connection_rows.{hpp,cpp}`). `/api/tcp` and `/api/udp` return
  the same fields and values as before.
- New `GET /api/connections[?pid=X]` returns `{tcp, udp, active_pids}` in one
  request and one strand hop: `tcp` / `udp` equal `/api/tcp` / `/api/udp`
  for the same filter, `active_pids` lists every PID owning a socket in the
  unfiltered listing. The UI's separate 10 s activity poll (`/api/tcp` +
  `/api/udp`) is merged into the 2 s connection poll, which now uses this
  endpoint: 72 → 30 requests a minute while the network tab is visible. The
  process tree's activity stamps refresh at most every 10 s, so it still
  re-renders at the old rate.

- Network activity shows what decided each connection (ROADMAP v0.14 #4).
  The 代理 column becomes 代理 · 规则 (still five columns): the verdict, then
  the rule name from the recorded decision (resolved through the rules list;
  `已删除的规则` once the rule is gone), `手动` for a manual hijack, or — for
  connections a reason decided regardless of rules — `决定过晚`, `看门狗放行`,
  `暂存池已满`, `IPv6 未接管`. Two quiet markers follow: a conflict icon when
  another enabled rule also matches the process, and a history icon
  (`规则已变更`) when the decision was recorded under an older routing
  configuration than the current one (old connections keep their original
  decision). Rows without a record show the current rule prefixed `≈`
  (estimated). The tooltip spells out rule (and whether it was inherited
  through the process tree), reason, record time, the change hint and the
  conflict ("A 先匹配并生效，B 被忽略"). Sortable by rule (the header's
  `规则`) and searchable by rule name, `冲突` and `规则已变更`.
- `/api/tcp`, `/api/udp`, `/api/connections` rows gain optional
  `conflict {manual, winner, shadowed_rule_ids}` (present only when more
  than one enabled rule — or a manual hijack plus rules — claims the
  process, under the current rules) and, on recomputed rows of a proxied
  process, `estimate {source, rule_id}`. `/api/connections` adds the
  engine's `config_version` from the same strand hop, so the UI compares
  `decision.config_version` against a consistent value. Conflicts are
  computed in the existing strand snapshot, once per distinct proxied PID
  (one `matched_pids` lookup per rule), not on the CONNECT path.
- Overlapping rules: the first matching rule in config order now decides
  the process consistently. A bulk rule apply (startup, any rule edit) used
  to let the LAST matching rule's proxy group win while the FIRST rule's
  protocol and destination filters applied; now the first rule's group,
  filters and decision-record rule all agree. A process that starts after
  the rules load is now checked against every rule (as the bulk apply does)
  so shadowed rules list it too.

### Removed

- Unused frontend API helpers `getHijackedProcesses` and `batchHijack`
  (`frontend/src/api/client.ts`), and `getTcpConnections` /
  `getUdpConnections` / `getNetworkConnections`, replaced by
  `getConnections`. The backend endpoints (`GET /api/hijack`,
  `POST /api/hijack/batch`, `/api/tcp`, `/api/udp`) are unchanged; tests and
  the stress harness still use them.

### Tests

- The older C++ unit tests now run in CTest on every CI build:
  `components_tests` (test_components.cpp), `icon_resolution_tests` and
  `window_dpi_tests` (built only with WebView2 enabled; embeds the
  production manifest at asInvoker). The Zig-only
  `tests/run_window_dpi_tests.py` runner is removed.
- `decision_log_tests`: ring wraparound and eviction, port reuse chain,
  lookup by key, IPv6 vs IPv4 keys, concurrent writers and readers (no torn
  record). `e2e_rule_policy.py` checks a proxied and a rule-excluded live
  connection show the matching `decision` in `/api/tcp`, and that deleting
  the rule leaves the recorded verdict unchanged; `e2e_api_test.py` checks
  every TCP row's `decision_source`.
- Rule conflicts: `route_policy_tests` covers conflict enumeration (config
  order, disabled rules, process started after the rules, tree inheritance
  vs a name match, manual hijack, per-process exclusion) and that the
  winner's group / policy row / filter apply; `connection_rows_tests` pins
  the `conflict` / `estimate` keys; `e2e_rule_policy.py` adds a shadowing
  rule for the live decision probe and checks both rows name the winner and
  the shadowed rule, then that deleting the shadowed rule clears the
  conflict while the recorded decision is now older than `config_version`.
  Vitest covers the 代理 · 规则 cell (recorded, recomputed, stale, ignored
  reasons, conflict, deleted rule) and `config_stale`. The WebView2
  screenshot harness runs a holding SOCKS5 server and renamed python
  helpers (two overlapping rules, a manual hijack as the routing change)
  and screenshots the filtered network view in both themes plus the cell
  tooltip, failing on missing markers or a clipped rule name.
- `connection_rows_tests`: every branch of the row → JSON builder (recorded
  proxied / direct / late / watchdog, listening, recomputed, dead PID, UDP
  with and without destination) including exact-byte golden rows.
  `e2e_api_test.py` pins the `/api/tcp` / `/api/udp` field set per branch and
  checks `/api/connections` against `/api/tcp?pid=` / `/api/udp?pid=` and
  that `active_pids` ignores the filter. The stress smoke polls
  `/api/connections` too and reports `late_rejected_proxied` before / after
  in `stress-summary.json`. Vitest covers the merged poll (one request per
  tick, activity fed while a PID is selected, 30 requests a minute).

## v0.13.1 — 2026-11-07

Patch release: concurrency and privilege-boundary fixes, plus cheap
correctness fixes from the v0.13.0 review. Several fixes change behaviour;
see **Changed**.

### Security

- Autostart: enabling "登录 Windows 后自动启动" is refused (HTTP 409,
  `details.code = "unsafe_install_location"`) unless proxyclaw.exe's folder,
  the files in it (DLLs, driver, config), `frontend/` and every parent folder
  can be modified only by Administrators / SYSTEM / TrustedInstaller — e.g.
  `C:\Program Files\ProxyClaw`. The elevated, prompt-less logon task
  previously pointed at wherever the zip was extracted (often Downloads),
  letting any unelevated process of the user swap the exe, plant a DLL or
  edit the UI and get admin rights at the next logon. An existing task that
  launches an exe from an unsafe folder is reported in Settings and the log
  (`task_trusted=false`); it is not deleted automatically. In Settings the
  switch is disabled with an explanation when the folder is not admin-only
  (turning an existing task off still works).
- `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at startup: DLLs
  loaded by name at runtime no longer come from the exe folder.
- Release builds ignore `PROXYCLAW_DEV_URL`, `PROXYCLAW_API_TOKEN` and the
  `WEBVIEW2_*` overrides (remote debugging port, browser executable folder,
  ...) and remove them from the process environment; user environment
  variables are writable without elevation. Pass `--dev-hooks` on the
  elevated command line (or use a debug build) to honour them.

### Fixed

- Proxy groups: editing groups/rules while proxied connections arrive no
  longer races the relay (the TCP group map was cleared and refilled on the
  API thread while relays read it). Relays now read an immutable snapshot
  that is swapped whole.
- Window geometry is saved through the config store (same lock as API
  edits), debounced to 500 ms after the last move/resize and off the UI
  thread; every config save uses its own temp file. Previously the UI thread
  wrote the config unlocked and could tear it.
- IPv6 is no longer misjudged as IPv4: the TCP SOCKET layer read an IPv6
  remote's low 32 bits as an IPv4 address, evaluated rules against it and
  could publish a bogus "proxied" decision for the port (the flow itself
  went direct). Both SOCKET layers now ignore CONNECTs to real IPv6 remotes
  and count them (`ipv6_unmanaged`, see Changed); the TCP and UDP NETWORK
  filters gain `ip and`, so IPv6 packets are no longer diverted to user mode
  just to be re-injected. IPv6 traffic still goes direct (not proxied).
- Per-process exclusions (此进程不走代理) no longer come back for dead or
  recycled PIDs: they were written into the config copy, only the engine
  copy was cleaned on process exit, and every later config change copied
  dead PIDs back.
- Process tree: children waiting for a not-yet-seen parent (orphans) are
  tracked by (pid, psn) instead of a tree index that compaction renumbers,
  which could re-parent an unrelated process (wrong tree-rule inheritance).
  Orphans now expire after 10 s (also swept after each lost-event rundown)
  and are capped at 4096; before, they were only flushed once at startup.
  The tree manager's timers now run on its strand.
- Process tree: the initial ETW rundown is verified against the OS process
  list. A CAPTURE_STATE issued before the real-time consumer had attached
  could be dropped by the kernel, leaving the tree at ~20 of ~150 processes
  for the whole session; the grace timer now re-issues capture_state (up to
  5 attempts) until coverage is reached.
- `POST /api/hijack/{pid}` and batch hijack resolve a live PID the tree has
  not seen yet (younger than the ETW ProcessStart latency) from the OS
  instead of answering 404.
- WinDivert shutdown follows WinDivertShutdown → join → WinDivertClose
  (handles were closed while worker threads were blocked on them); the
  NETWORK queues drain instead of being dropped; unexpected receive errors
  back off.
- HTTP API start-up binds synchronously and reports a bind failure instead
  of assuming success after 100 ms.
- Process tree: the PID column has a fixed 5-digit width (row gap 6px ->
  4px), so whether a deep name such as proxyclaw.exe fits no longer depends
  on how many digits its PID has.

### Changed

- Autostart only from an admin-only install folder; otherwise 409
  `unsafe_install_location` (see Security).
- Dev/test environment hooks need `--dev-hooks` in release builds (see
  Security).
- Proxy group validation (`POST/PUT /api/proxy-groups`, and `proxy_groups`
  in `PUT /api/config`): 400 with `details.field` for a port outside
  1-65535 (70000 used to be stored as 4464), an empty host or `host:port`,
  a type other than `socks5`, or a non-empty user/password (only SOCKS5
  without authentication is implemented). `[v6]` hosts are stored without
  brackets, and the relay, UDP session and speed test resolve the same
  normalised host. The proxy group dialog validates the same way (port must
  be an integer 1-65535, no silent fallback to 7890; host must not be empty
  or include a port; errors under the field) and notes that only SOCKS5
  without authentication is supported.
- `POST /api/hijack/{pid}` and `/api/hijack/batch` answer 400 for a
  `group_id` that does not exist, instead of hijacking the process into a
  group whose connections the relay then drops.
- Per-process exclusions are runtime state owned by the rule engine, keyed
  by (pid, process sequence number): never persisted or read from the
  config, kept across rule reloads, dropped on process exit, ignored for a
  recycled PID. `POST /api/auto-rules/{id}/exclude/{pid}` answers 404 for a
  process that is not running. The API/UI contract (`excluded: true` in rule
  JSON) is unchanged.
- `GET /api/stats` gains `ipv6_unmanaged: {tcp, udp}` (CONNECTs to IPv6
  remotes that ProxyClaw does not take over), `tree_ready` and
  `process_count`.
- Proxied TCP :53 (e.g. Chrome's built-in resolver over TCP) is sent to
  `dns.upstream_host:dns.upstream_port` instead of a hardcoded 8.8.8.8:53,
  whether or not the DNS proxy is enabled. Falls back to 8.8.8.8:53 (with a
  log warning) when the upstream is not a usable IPv4 address.
- Console mode (no window) runs until Ctrl+C / console close instead of
  exiting after one hour; without WebView2 the GUI build shows a dialog with
  the browser URL and runs until it is closed.

### Tests / CI

- New CTest suites: `runtime_state_tests` (exclusion keying and PID reuse,
  orphan resolution after compaction, orphan expiry/cap, group validation,
  IPv6 event classification, TCP :53 upstream selection),
  `concurrency_tests` (group snapshot swap, debouncer, concurrent config
  writes) and `path_trust_tests` (install-location DACL check against real
  ACLs, dev-hook gating). `tcp_redirect` checks that the NETWORK filter no
  longer matches IPv6.
- e2e: group validation (POST/PUT/config), hijack into a missing group,
  exclusion surviving a config reload and ending with the process,
  `ipv6_unmanaged` in stats. Vitest: proxy group form validation and the
  autostart warning states.
- e2e/screenshot/stress harnesses launch proxyclaw.exe with `--dev-hooks`
  and wait for `tree_ready` instead of sleeping; the DELETE <60ms check times
  only the API round-trip; system DNS is read via GetAdaptersAddresses
  instead of a cold PowerShell `Get-DnsClientServerAddress`; log-scan
  asserts retry the read until quill has flushed.
- WebView2 screenshot harness: `wait_for_function` polls on a 200 ms timer
  instead of requestAnimationFrame (a reload could leave the page producing
  no frames, so the rAF predicate never re-ran), the CI WebView2 runs with
  occlusion / background throttling disabled, and the page state after the
  reload is written to console.log.

## v0.13.0 (2026-11-07)

### Frontend

- Network: per-process exclude. When an auto rule proxies the selected
  process, the header ⋯ menu offers 此进程不走代理 (excludes that PID from
  every matching rule; runtime only, 进程重启后恢复) and 恢复代理 to undo
  it. Excluded processes show an 已排除 tag in the header and a hollow dot
  (tooltip 已排除) in the process tree;
  the rule editor lists the processes a rule matches, with 恢复 on excluded
  ones. The auto-proxy dot now also shows for `auto:<rule>` sources.
  Backend: `GET /api/auto-rules` now also lists live excluded PIDs in
  `matched_pids` (`excluded: true`).
- Layout restructured after magpie: the title bar and tabs are one 44px bar
  (logo, centred tabs 网络 · 规则 · 代理 · 设置, a `● 18080` status chip,
  theme and window buttons). The footer is gone; the version moved to
  设置 › 关于. Tab bodies are centred (max 1200px) and fade in on switch.
- The process tree shows only on the Network tab, at a fixed 240px
  (resizable, no border). Guide lines only for active subtrees, idle rows
  muted instead of faded, search matches in bold, 手动/自动 as a dot with a
  tooltip.
- Network: the selected process is a 48px header row (PID · path, 创建规则)
  above the search and count. The path middle-truncates inside the
  directory only (`D:\a\proxy…\win\proxyclaw.exe`); copy and reveal
  overlay the path end on hover with a fade and take no width otherwise. The
  table has 5 columns and 32px rows without pills: protocol is a faint
  prefix of the remote address, PID a muted suffix of the process name.
- Rules: one list of ~52px rows with the process icon, a sub-line, an
  inline proxy-group select, the switch and a ⋯ menu (edit, delete). The
  icon swaps to a checkbox on hover or while selecting, so there is no
  checkbox gutter; bulk actions are unchanged.
- Proxies: one list of 48px rows (`SOCKS5 · host:port · N 条规则`, latency,
  test, ⋯); a row expands inline to show the test URL, the last result and
  its rules; clicking a rule opens the shared rule editor.
- Primitives: 13px base text, filled borderless fields with an inset focus
  ring, trackless segmented controls, press feedback on buttons, text-only
  empty states, no text selection on app chrome, monospace only for the
  JSON editor, logs and command lines, 4px spacing grid.

### Docs and CI

- README.md / README.en.md rewritten around the current React UI with new
  screenshots taken by the CI WebView2 screenshot test; new
  `docs/ROADMAP.md` (v0.13, v0.14, later). One-off review / fix notes,
  `docs/history`, `tools/research`, the bundled WinDivert HTML doc,
  `sonar-project.properties` and the Vue-era screenshots are removed.
- Local-only test scripts that neither CI nor CTest ran are removed;
  `scripts/verify.py` runs `tests/e2e_rule_policy.py` as its e2e stage.
- CI now runs the API e2e test (`tests/e2e_api_test.py --exe`, with a
  recording SOCKS5 server) and a bounded 45 s stress smoke
  (`tests/stress_backend.py --ci`) against the packaged app, and uploads a
  `stress-summary` artifact. Build job timeout raised to 40 minutes.

## v0.12.0 (2026-11-04)

### Frontend

- Rewritten from Vue 3 to React 19 + TypeScript (Vite 7, Tailwind CSS 4).
  Vue, reka-ui, AG Grid, Monaco and the DOMPurify alias are gone. Same
  features, same API calls, same Chinese UI and dark / light themes.
- One library per concern: TanStack Query holds all server state. The
  hand-written `asyncPoller` is replaced by `refetchInterval` with
  `refetchIntervalInBackground: false`, so every poll (stats 3 s, connections
  2 s, process activity 10 s, logs 3 s) pauses while the window is hidden and
  refetches once on restore. The WebView2 push channel only writes the cache:
  `process_update` → `setQueryData`, `auto_rule_changed` → invalidates rules
  and stats (the rule list now refreshes on that push).
- Process tree and network table are virtualized with TanStack Virtual. The
  table keeps column sort (asc → desc → off), the quick filter (now also
  matches the Chinese state labels), the `route_reason` tooltip and the
  struck-through rows for exited processes.
- Raw JSON config editor: CodeMirror 6 with JSON lint, loaded on demand;
  Ctrl+S saves.
- Radix primitives (dialog, select, switch, tooltip, tabs), Sonner toasts
  (replace the status-bar message), React Hook Form + Zod for the rule editor.
- Calmer layout: neutral low-saturation palette, segmented tabs, settings
  grouped into card lists, more whitespace.
- Process tree: indentation grows for the first 5 levels, then stays put;
  deeper rows draw a dashed guide and show their depth in the tooltip. Names
  that still do not fit end in an ellipsis with the full name on hover, so
  deep processes no longer slide out of the sidebar (no horizontal scroll).
- Eagerly loaded JavaScript: about 1.1 MB → 620 kB (index 78 kB + react
  222 kB + vendor 319 kB; 196 kB gzipped). The 358 kB editor chunk loads only when the JSON
  editor opens.
- `npm audit`: 0 vulnerabilities. Tests: data layer (polling, pause while
  hidden, push → cache), table sort / filter, tree helpers, form mapping, and
  an App smoke test under jsdom.

### API

- `GET /api/icon` answers 204 No Content (empty body, not cached) when the
  executable has no extractable icon, instead of 404. The UI shows its
  generic icon without a failed image load in the console. A missing `name`
  is still 400.

### CI

- GitHub Actions moved to Node 24 releases (checkout v6, setup-python v6,
  setup-node v6, upload-artifact v6, download-artifact v7).
- The packaged app is opened in a real WebView2 window and screenshotted over
  CDP; any console error, page error or truncated name of the selected
  (deeply nested) process fails the build.

## v0.11.1 (2026-11-03)

### Frontend

- Dependencies: `npm audit` now reports 0 vulnerabilities (was 15: 2 critical,
  10 high). Vue, Vite and their transitive deps updated in range; Vitest
  3 → 5; Monaco Editor 0.55 → 0.57.
- Monaco bundles its own copy of DOMPurify (3.4.15, several XSS advisories).
  The build now aliases Monaco's sanitizer import to the npm `dompurify`
  package (pinned ≥ 3.4.17 via `overrides`), so the shipped editor uses the
  patched version.
- Monaco 0.57 import paths: deep imports follow the package's new `exports`
  map (`monaco-editor/editor/...`); the Chinese language pack moved to
  `monaco-editor/nls/lang/zh-cn.js`.
- Bundle split: the network table registers only the AG Grid modules it uses
  instead of `AllCommunityModule`, and vendor libraries go into separate
  chunks. The eagerly loaded JavaScript drops from about 1.5 MB to 1.1 MB
  (main app chunk 1,495 kB → 106 kB). Monaco chunks remain lazy and load only
  when the JSON editor opens.

## v0.11.0 (2026-11-02)

### UDP

- First-packet parking: a datagram sent right after a socket's implicit bind
  could reach the NETWORK layer before the BIND decision was published and
  leave direct. Datagrams from a port with no decision yet are now held until
  the decision (then proxied or sent direct per the rule), at most 20 ms;
  past that they go direct and the port is pinned direct until it closes
  (sockets opened before ProxyClaw started pay this once). The SOCKET layer
  now records "direct" decisions too, including ProxyClaw's own sockets.
  Kill switch and tuning: `udp_first_packet.enabled` / `watchdog_ms`
  (5..50, startup only). The e2e UDP probe no longer waits after binding.

### CI

- The loopback network suites now run in CI: `proxy_health_harness` (TCP relay
  and SOCKS5 UDP session, 23 cases) and `dns_forwarder_harness` (DNS forwarder
  UDP/TCP fallback, 22 cases) are CMake targets built with the release
  toolchain and driven by `tests/run_proxy_health_tests.py` /
  `tests/run_dns_network_tests.py --exe`.
- The IPv6 UDP bulk-cleanup case (96 create/cleanup/recreate cycles), which
  had been timing out, passes. The proxy-health harness kept the 4 MiB
  `PortTracker` as a coroutine local, which overflowed the 1 MiB stack under
  MSVC; it is now heap-allocated.

### Build

- No compiler warnings: the projection snapshot uses a mutex instead of the
  deprecated `std::atomic_load/store` on `shared_ptr`, and the UI config test
  guards its `WIN32_LEAN_AND_MEAN` / `NOMINMAX` defines.

## v0.10.3 (2026-11-02)

### Rules

- One destination verdict for TCP, UDP and the UI. `include_cidrs`,
  `include_ports` and `exclude_ports` in a rule's `dst_filter` now take effect
  on the data path; before, only `exclude_cidrs` did, so "proxy ports" in the
  rule editor changed the UI label but not the traffic.
- TCP honours the rule's `protocol`: a UDP-only rule no longer proxies the
  process's TCP connections.
- The connection list reports what the data path decided, including global
  excludes for manual hijacks, and returns a `route_reason`; the UI shows it on
  hover over "Ignored".
- The rule editor exposes all four filter fields. Saving a rule no longer wipes
  `include_cidrs` / `exclude_ports` set in the config file.

### UDP

- Per-packet addressing. A proxied datagram now travels to the relay with its
  own destination instead of a per-socket entry that every packet overwrote, so
  a socket that sends to several peers (DNS to two resolvers, STUN/WebRTC,
  games, QUIC) no longer has datagrams sent to the wrong peer.
- Replies are injected with the real responder's address from the SOCKS5
  header (before: the last destination), and only from peers the socket sent
  to.
- A slow proxy handshake for one socket no longer stalls every other UDP
  socket; the relay queues per socket with fixed limits and drops (and counts)
  the excess. The relay no longer binds local UDP port 19999.
- Fix: a UDP socket that sent to one excluded destination (e.g. a LAN
  resolver) stopped proxying all of its other destinations too. Excludes are
  now decided per packet only.

### Proxy speed test

- Rewritten (`src/proxy/proxy_probe.*`). Runs on its own io_context with an
  8 s overall deadline; before, a dead proxy could block an API worker in a
  connect with no timeout.
- Proxy host may be IPv4, IPv6 or a domain name (before: IPv4 literal only).
  A domain with several addresses is connected happy-eyeballs style (IPv6 and
  IPv4 interleaved, next attempt after 250 ms or on failure), so `localhost`
  no longer waits ~2 s on a refused `::1`.
- The test URL's scheme and port are honoured: https uses 443 and waits for a
  TLS ServerHello instead of sending plain HTTP to port 80.
- The SOCKS5 CONNECT reply is read in full for every address type.
- Timed by stage (resolve, connect, handshake, remote, first byte); a failure
  names its stage and the SOCKS5 reply code. The UI shows the breakdown and
  adds "Test all"; at most 4 tests run at once.

### Tests

- New `route_policy_tests`, `udp_flow_tests` and `proxy_probe_tests` under CTest.
- `tests/e2e_rule_policy.py` runs in CI on the elevated Windows runner with the
  real WinDivert driver: rule filters over TCP, and UDP from one socket to two
  destinations through a SOCKS5 UDP relay.

## v0.10.2 (not released on its own; included in v0.10.3)

Engineering and security cleanup. No change to traffic forwarding.

### Security

- The local management API now requires a per-launch session token on every
  `/api/` request, checks the `Host` header (DNS rebinding) and rejects foreign
  `Origin`s. Wildcard CORS and the blanket `OPTIONS` handler are removed. The
  window obtains an `HttpOnly; SameSite=Strict` cookie through
  `/api/session`; the token is redacted from logs. See
  `docs/ARCHITECTURE.md` → API Endpoints → Access control.
- WebView2 web messages are accepted only from the page the host navigated to.

### Tests and CI

- Native unit tests run under CTest and in CI: api_auth, dns_wire,
  dns_manager, ui_config, config_migration, log_tail, projection (previously
  only tcp_redirect ran in CI).
- Frontend unit tests moved to Vitest (`npm test`), run in CI.
- Layering checks moved to `scripts/check_layering.py` and run in CI;
  `scripts/verify.sh` replaced by `scripts/verify.py`.
- Test harnesses share the API token with the process they launch
  (`tests/api_token.py`).
- `run_proxy_health_tests.py --baseline` points at a commit that exists
  (`5b93eb0`).

### Build

- CMake presets `windows`, `windows-vs2026` and `windows-clangd` use the same
  pinned, checksum-verified dependencies as CI
  (`scripts/prepare_release_deps.py`), with build and test presets.
  `windows-vcpkg` remains for classic-mode vcpkg users.
- Removed the unused `radix-vue` dependency.

### Docs

- README build steps follow the new presets; removed references to
  private paths and to commits lost in the history rewrite.
