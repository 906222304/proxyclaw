# Changelog

## Unreleased

### Backend

- Process tree: the initial ETW rundown is now verified against the OS
  process list. A CAPTURE_STATE issued before the real-time consumer had
  attached could be dropped by the kernel, leaving the tree at ~20 of ~150
  processes for the whole session; the grace timer now re-issues
  capture_state (up to 5 attempts) until coverage is reached.
  `GET /api/stats` gains `tree_ready` and `process_count`.
- `POST /api/hijack/{pid}` and batch hijack resolve a live PID the tree has
  not seen yet (younger than the ETW ProcessStart latency) from the OS
  instead of answering 404.

### Frontend

- Process tree: the PID column has a fixed 5-digit width (row gap 6px -> 4px),
  so whether a deep name such as proxyclaw.exe fits no longer depends on how
  many digits its PID has.

### Tests / CI

- e2e/screenshot/stress harnesses wait for `tree_ready` instead of sleeping;
  the DELETE <60ms check times only the API round-trip; system DNS is read
  via GetAdaptersAddresses instead of a cold PowerShell
  `Get-DnsClientServerAddress`; log-scan asserts retry the read until quill
  has flushed.
- WebView2 screenshot harness: `wait_for_function` polls on a 200 ms timer
  instead of requestAnimationFrame (run 42372296123 timed out on `#root`
  after the reload while the reloaded app was alive and polling the API: no
  frame was produced, so the rAF predicate never re-ran), the CI WebView2
  is started with occlusion / background throttling disabled, and the page
  state after the reload (visibility, focus, rAF, `#root` children) is
  written to console.log.

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
