# ProxyClaw Architecture

Contributor-facing technical overview. For the end-user intro see [README.md](../README.md).

## Tech Stack

- **Language**: C++23 (concepts, C++20 coroutines for relay, `using enum`, fold expressions)
- **Build**: CMake + pinned dependencies (`scripts/prepare_release_deps.py`)
- **Core deps**: WinDivert (kernel traffic intercept), WebView2 (embedded browser UI)
- **Backend libs** (pinned, checksum-verified): `quill` (logging), `nlohmann-json`, `cpp-httplib`, `asio` (standalone)
- **Frontend**: React 19 + TypeScript + Vite 7 + Tailwind CSS 4; TanStack Query (all server state: polling via `refetchInterval`, push writes into the cache), TanStack Virtual (process tree + network table), Radix primitives, CodeMirror 6 (JSON-only, lazy-loaded)
- **IPC**: HTTP API for CRUD + WebView2 in-process PostMessage for backend → frontend push (replaces the previous SSE channel)
- **Config**: JSON (`proxyclaw.json`)
- **Target**: Windows 10 2004+ / 11 (requires `SetInterfaceDnsSettings`), administrator privileges

## Project Structure

The codebase is organized as a four-layer architecture: **domain** → **application services** → **transport**, with a **projection** layer materializing strand state for HTTP responders and the WebView2 push channel. `clew::app` (`src/app.{hpp,cpp}`) is the single owner of the runtime object graph; `main.cpp` is the thin entry adapter (parse args, RAII guards for single-instance / debug console / Winsock, then construct + run the app).

```
src/
  main.cpp                       - thin entry: WinMain/main → run_app() → clew::app
  app.{hpp,cpp}                  - composition root, owns ~30 subsystem members,
                                    explicit shutdown order in dtor

  common/                        - cross-layer utilities
    api_context.hpp                  - DI aggregate of service refs passed to handlers
    api_exception.{hpp,cpp}          - api_error enum + api_exception (throwable across layers)
    json_patch.hpp                   - apply_patch + field_binding template (whitelisted PATCH)
    process_tree_json.hpp            - shared process-tree → JSON serialization
    winsock_session.hpp              - RAII WSAStartup / WSACleanup
    single_instance_guard.hpp        - RAII single-instance mutex
    debug_console_session.hpp        - RAII AllocConsole / FreeConsole

  config/
    types.hpp                    - All data types: AutoRule, ProxyGroup, DnsConfig, ConfigV2
    config_manager.hpp           - JSON config persistence (proxyclaw.json)
    config_change_tag.hpp        - observer dispatch tag enum
    config_store.{hpp,cpp}       - thin wrapper: mutate(fn, tag) + observer fanout

  domain/                        - strand-bound application kernel
    strand_bound.hpp                 - concept-constrained query/command template
    tree_change_receiver.hpp         - listener interface (on_tree_changed / on_process_exit)
    process_tree_manager.{hpp,cpp}   - owns flat_tree + rule_engine + ETW driver

  services/                      - 8 application services (HTTP-facing logic)
    config_service / connection_service / group_service / icon_service /
    process_tree_service / rule_service / shell_service / stats_service

  projection/                    - state holders bridging domain → transport / UI
    process_projection.{hpp,cpp}     - tree_change_receiver: maintains atomic snapshot
                                       + pushes through frontend_push_sink with a
                                       100 ms strand-timer coalesce window for
                                       push_urgency::batched events
    config_sse_bridge.{hpp,cpp}      - config_store observer → push auto_rule_changed
                                       (file name retained for git history; the sink
                                       is now PostMessage, not SSE)

  transport/                     - HTTP API server + push channel interface
    http_api_server.{hpp,cpp}        - cpp-httplib server + 8-worker thread pool
    middleware.{hpp,cpp}             - CORS / OPTIONS / cache headers (post-routing)
    route_def.hpp                    - {method, pattern, handler} descriptor + http_method enum
    route_registry.{hpp,cpp}         - dispatcher: 3-tier exception catch + per-request log
    response_utils.{hpp,cpp}         - json body helpers (parse_json_body / write_json)
    frontend_push_sink.hpp           - push(event, json_body) interface; the
                                       projection layer calls it from any thread,
                                       webview_app marshals onto the UI thread
    handlers/                        - 9 thin route modules (one per resource group)

  core/                          - low-level infrastructure
    log.hpp                          - quill wrapper, PC_LOG_* macros + runtime set_log_level
    scoped_exit.hpp                  - unique_handle (Win32 HANDLE RAII) + scoped_exit<F>
    string_hash.hpp                  - transparent string_hash + string_map<V> alias
    port_tracker.hpp                 - atomic array[65536]: per local port, a four-state word {state|gen|pool idx} + timestamps + entry
    syn_parker.hpp                   - SYN parking: bounded packet pool + injector thread (release / watchdog sweep)
    windivert_socket.hpp             - TCP SOCKET SNIFF: CONNECT -> one published decision (proxied/direct), CLOSE -> slot cleanup
    windivert_network.hpp            - TCP NETWORK reflection: parks undecided SYNs, reflects proxied flows
    dns_forwarder.hpp                - UDP DNS listener, forwards via SOCKS5 UDP ASSOCIATE
    dns_manager.hpp                  - dns_forwarder lifecycle + system DNS state
    system_dns.hpp                   - Win32 SetInterfaceDnsSettings + dns_state.json persist

  process/                       - process discovery + tree
    flat_tree.hpp                    - vector<process_entry> + LC-RS indices, O(1) PID lookup
    etw_consumer.hpp                 - ETW real-time ProcessStart / ProcessStop consumer
    ntquery_snapshot.hpp             - Initial full process snapshot via NtQuerySystemInformation
    tcp_table.hpp / udp_table.hpp    - OS connection table queries

  rules/                         - auto-rule matching + traffic filtering
    rule_engine_v3.hpp               - flat_tree flag-based engine, no mutex
    traffic_filter.hpp               - CIDR / port destination filter
    policy_table.hpp                 - immutable dst-exclude table, published on
                                       config change; UDP workers read it lock-free

  proxy/                         - TCP relay
    acceptor.hpp                     - Asio TCP acceptor, spawns relay coroutines
    relay.hpp                        - C++20 coroutine bidirectional pipe + SOCKS5 handshake
    socks5_async.hpp                 - Async SOCKS5 handshake coroutine

  udp/                           - UDP relay (mirrors TCP, per-app-port sessions)
    windivert_socket_udp.hpp / windivert_network_udp.hpp
    udp_port_tracker.hpp / udp_session_table.hpp / udp_relay.hpp
    udp_flow.hpp                     - per-datagram handoff type, peer set, queue limits
    udp_first_packet.hpp             - first-packet parking (datagrams of undecided ports)
    socks5_udp_manager.hpp / socks5_udp_session.hpp / socks5_udp_codec.hpp

  api/
    icon_cache.hpp                   - GDI+ icon extraction + PNG cache (AUMID-aware)

  ui/
    webview_app.hpp                  - Frameless WebView2 host + tray; WndProc dispatcher

frontend/                            - React 19 + TypeScript (built static files served by cpp-httplib)
tests/
  test_*.cpp, log_tail_test.cpp      - native unit tests registered in CTest (see CMakeLists.txt)
  proxy_health_harness.cpp,
  dns_forwarder_harness.cpp          - loopback integration hosts, driven by run_proxy_health_tests.py
                                       and run_dns_network_tests.py in CI
  e2e_rule_policy.py                 - real-WinDivert rule / UDP / speed-test e2e (CI, admin)
  e2e_api_test.py                    - management API e2e against the packaged exe (CI, admin):
                                       stats/tables, icon 200/204/400, rule + group CRUD, exit routing
                                       of fresh probe processes, hijack/batch notify, config observers,
                                       DNS proxy round trip. --exe launches proxyclaw with a recording
                                       SOCKS5 server; without it, attaches to a running instance
  api_token.py                       - shared PROXYCLAW_API_TOKEN for the Python harnesses
  stress_backend.py                  - backend stress + measurement; --ci is the bounded CI smoke
                                       (ETW churn, hijack cycling, concurrent GETs, proxyclaw RSS /
                                       handles); fails on errors or a crash, never on numbers.
                                       Summary uploaded as the `stress-summary` artifact
  stress_etw.py                      - ETW process-churn driver (no admin), spawned by stress_backend
  ui_webview2_screenshots.py         - packaged app in a real WebView2 window, screenshots over CDP (CI)
  test_components.cpp, test_window_dpi.cpp, test_icon_resolution.cpp
                                     - older unit tests not yet in CTest (run_window_dpi_tests.py)
  network_fakes/ dns_fakes/ projection_fakes/ - header fakes for the unit tests
scripts/
  verify.py                          - one-shot: frontend tests/build + cpp build + ctest + layering
                                       grep guards + real-WinDivert e2e (admin)
assets/
  clew.svg / clew.ico / clew.rc      - Embedded Windows icon
```

## Key Architectural Decisions

### Core runtime: single io_context + strand

- One `asio::io_context` with configurable worker threads (`io_threads`, default `hardware_concurrency() / 2`)
- One shared `strand` serializes all process tree + rule engine mutations (zero mutex in hot path)
- ETW events, process start/stop, rule changes all dispatched through the strand

### Process tree: ETW + NtQuery snapshot + Flat Tree

- Real-time ETW `ProcessStart` / `ProcessStop` instead of polling
- `ntquery_snapshot` provides the initial full tree; ETW maintains it incrementally
- `process_tree_manager` orchestrates: ETW + NtQuery + Flat Tree + Rule Engine

### Flat Tree with LC-RS (Left-Child Right-Sibling)

- `flat_tree.hpp`: `std::vector<process_entry>` + `std::unordered_map<DWORD, uint32_t>` side map
- Each entry stores `{pid, parent_pid, create_time, name_u8[780], parent_index, first_child_index, next_sibling_index, flags, group_id, cmdline_cache}`
- O(1) lookup by PID via side map, O(subtree) traversal via LC-RS indices
- `flags` field stores hijack state directly on the entry (no separate map)
- `group_id` field stores proxy group assignment (read by SOCKET layer in hot path)
- Tombstone + compact: dead entries marked, auto-compacted when tombstones > 20% alive

### Backend → frontend push: WebView2 PostMessage

Replaces the earlier SSE / `EventSource` channel. Push events flow:

1. A domain mutation (ETW process start/stop, manual hijack, rule reload) calls
   `process_tree_manager::notify_tree_changed(urgency)` on the strand.
2. `process_projection::on_tree_changed` rebuilds the atomic snapshot and
   pushes immediately (default build). The `push_urgency` hint distinguishes
   user actions (`immediate`) from background ETW (`batched`); see "Coalescing"
   below for the optional compile-time switch.
3. Projection calls `frontend_push_sink::push("process_update", json)`.
4. `webview_app::push` allocates a `push_payload` and posts a custom
   `WM_PUSH_TO_FRONTEND` to the UI thread, so cross-thread marshalling is
   explicit across HTTP workers, ETW threads, and the strand.
5. The UI-thread WndProc takes ownership, builds `{event, data}`, and calls
   `ICoreWebView2::PostWebMessageAsJson`.
6. Frontend's `notify.ts` listens on `chrome.webview` `message` events and
   writes the TanStack Query cache (`setQueryData` for `process_update`,
   `invalidateQueries` for `auto_rule_changed`); components read it through
   `useQuery`.
7. Initial sync: when the frontend mounts (or when visibility transitions
   from hidden back to visible) it posts `{type: 'ready'}` back through
   `chrome.webview.postMessage`. The host invokes
   `process_projection::replay_to_frontend` to re-push the latest snapshot.

Why this transport:

- **In-process IPC**: no HTTP socket, no chunked SSE byte stream — V8's main
  thread is no longer busy parsing the push channel while it is also rendering.
- **No browser connection-limit interference**: HTTP/1.1 caps per-host
  connections (Chromium's default is 6); a long-lived SSE stream permanently
  occupied one of those slots, so bursts of concurrent CRUD calls had one
  fewer slot available. In-process IPC is independent of that pool entirely.
- **Simpler shutdown**: a single window message in flight at most, no
  long-lived HTTP connection to drain.

`/api/processes` (the snapshot endpoint that frontends used to poll) was
removed because the snapshot now arrives inside every `process_update` push;
nothing on the frontend needs to fetch the full tree any more. `/api/processes/:pid`
and `/api/processes/:pid/detail` are kept because they answer single-record
questions that the push channel does not duplicate.

#### Coalescing — compile switch `PROXYCLAW_PROJECTION_COALESCE`, ON since v0.10

A 100 ms refresh-coalesce window for `batched` urgency: the refresh happens
**inside** the timer callback, not per event, so a burst of hundreds of ETW
events collapses to a single refresh + push at the end of the window.
`immediate` urgency (user-driven: hijack, rules, exclusions) bypasses the
timer regardless. Since v0.10 **all** ETW-driven changes are `batched`,
including `etw_start` (it used to be `immediate`).

Why it is no longer optional: with SYN parking, CONNECT decisions run on the
same strand, and a decision that waits more than the parking watchdog (20 ms)
lets a connection go direct. ETW delivers a spawn loop's starts and stops
1–2 s later as one burst; measured, that burst of per-event refreshes
(~0.8 ms each for ~450 processes) held a decision past the watchdog once in
100 fresh connections. The trade-off — a new process shows up in the tree
up to 100 ms later — is not perceptible. The option is kept for
experiments (`cmake -DPROXYCLAW_PROJECTION_COALESCE=OFF`) but `CMakePresets.json`
pins it ON; an old `build/` cache keeps whatever it had, so reconfigure via
the preset.

### Visibility gate — minimize / tray drops backend work

When the WebView2 host is hidden (window minimized or in the tray), the
backend stops doing tree-snapshot work entirely. Implementation:

1. `webview_app::set_visible(bool)` is the single chokepoint. It's called
   from `WM_SIZE` (SIZE_MINIMIZED → false, SIZE_RESTORED / SIZE_MAXIMIZED →
   true), `on_close` close-to-tray (false), and `restore_window` (true).
   It toggles `ICoreWebView2Controller::IsVisible` (so `document.visibilityState`
   in the embedded page tracks reality) and fires a registered
   `on_visibility_change_` callback. Idempotent — repeated calls with the
   same state are no-ops, which matters for `WM_SIZE` chatter.
2. `app::wire_observers` wires the callback to
   `process_projection::set_frontend_visible(bool)`, which stores into a
   `std::atomic<bool> frontend_visible_` (relaxed memory order — this is
   a hint, not a strict barrier).
3. `process_projection::on_tree_changed` checks the flag at the very top
   and early-returns when hidden. No `refresh_snapshot`, no PostMessage,
   no V8 wake-up. The strand is free to serve other work (in practice
   there's nothing else to serve while the user has the window away).
4. The frontend mirrors the gate on the client side: the polled endpoints
   (`/api/stats`, `/api/tcp`, `/api/udp`, `/api/logs`) are TanStack Query
   queries with `refetchInterval` and `refetchIntervalInBackground: false`,
   so they pause while `document.visibilityState` is `hidden` and refetch
   once on restore (`frontend/src/api/queries.ts`).
5. When the host returns to visible, `set_visible(true)` does NOT replay
   automatically — instead, the frontend's `visibilitychange` handler
   re-posts `{type: 'ready'}`, which drives the existing replay path
   (`process_projection::replay_to_frontend`). The frontend gets a full
   fresh snapshot in one shot.

Net effect (measured under sustained 270 ETW events/sec at tree=1200):
strand utilisation 48% visible → 0.0% hidden, hijack wait_us tail 940 ms →
92 µs (any user CRUD waiting in the queue still completes; just nothing
new piling up). See the v0.8.9 release notes on GitHub.

### Autostart on logon (Task Scheduler, v0.9.0)

Settings → "Start ProxyClaw at logon" registers a Windows Task Scheduler entry that launches proxyclaw.exe at user login with the user's elevated token. The naive registry approach (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) would prompt UAC every login, since proxyclaw.exe needs admin for WinDivert and `SetInterfaceDnsSettings`. Task Scheduler with `/RL HIGHEST` skips the prompt.

- **`src/services/autostart_service.{hpp,cpp}`** — stateless static API (`query()` / `set(enabled, start_minimized)`). Implementation shells out to `schtasks.exe` (system32 absolute path, not PATH-dependent), captures stdout + stderr via anonymous pipes drained by `std::jthread`s in parallel (a single sequential drain deadlocks if schtasks writes more to stderr than the buffer holds). Command-line construction goes through a `quote_win_arg` helper that follows the `CommandLineToArgvW` rules so paths with spaces or quotes survive. State lives in the OS, not in `proxyclaw.json` — `query()` shells out fresh on every call so manual edits via `taskschd.msc` are reflected immediately in the UI.
- **`src/transport/handlers/autostart_handlers.cpp`** — `GET /api/autostart` returns `{enabled, start_minimized}`; `PUT /api/autostart` writes through to `autostart_service::set` and re-queries. No `api_context` dependency (mirrors `shell_service`).
- **`webview_app::start_minimized_`** — when set (via `--minimized` CLI arg or `app::create_gui` from `cli_options`), the host window goes through `SW_HIDE` instead of `SW_SHOW` (cleaner than `SW_MINIMIZE` — no taskbar flash). Once the WebView2 controller is created (asynchronously, in a callback), `IsVisible` is set to `FALSE` so `process_projection`'s `frontend_visible` gate (Visibility gate above) matches reality from `t=0` and no work piles up.
- **Task command line**: `"<exe-abs-path>" --config "<exe-dir>/proxyclaw.json"` plus `--minimized` if the sub-toggle is on. `--config` is pinned even though `exe_directory() / "proxyclaw.json"` is the default — explicit pinning self-documents the autostart contract in the task entry.

### Frontend HTTP CRUD: empty `body: ''` on DELETE

This is independent of the push-transport switch above — they were two
separate problems that happened to ship in the same release.

cpp-httplib (observed on v0.31; the build now pins v0.20.0) treats DELETE the same
as POST/PUT/PATCH: `expect_content()` returns true and the server's
`read_content_core` enters an `MSG_PEEK` block whenever the request has neither
`Content-Length` nor chunked `Transfer-Encoding`. With the default 100 MB
`payload_max_length` and 5 s `read_timeout_sec`, that peek waits the full
read timeout before the handler is even dispatched — even if the handler
reads no body. Browser `fetch` DELETE without an explicit body sends no
`Content-Length`, so an Unhack click stalled for ~5 s server-side before any
of our code ran.

The fix is on the client side. `frontend/src/api/client.ts` always passes
`body: ''` for DELETE-shaped CRUD calls (`unhijackProcess`, `deleteAutoRule`,
`unexcludePid`, `deleteProxyGroup`). The browser then emits
`Content-Length: 0`, cpp-httplib takes the fast path in `read_content` (length
0 → return immediately), and the handler runs in <2 ms. The server-side
alternative (`set_payload_max_length(SIZE_MAX)`) was avoided because it opens
the server to unbounded payload allocations; a one-line client change is the
proportional fix.

### WinDivert dual-layer

- **SOCKET SNIFF layer** (`windivert_socket.hpp`): observes `connect()` and `close()` events (filter `outbound and !loopback and tcp and (event == CONNECT or event == CLOSE)`). For every CONNECT it publishes exactly one decision into `PortTracker[local_port]`: `proxied(group)` or `direct`. Unknown PIDs (younger than the ~1–2 s ETW delivery) are resolved on the spot by `process_tree_manager::resolve_pid_now` (ancestor walk + insert with the real PSN, so the late ETW START is an idempotent no-op). Handler runs on the strand. IPv6 is out of the decision path (v0.13.1): an event on the IPv6 layer whose remote is not IPv4-mapped is counted (`ipv6_unmanaged`) and ignored — no decision is published and its CLOSE does not touch the IPv4 slot of the same port number. Previously its low 32 bits were evaluated as an IPv4 destination.
- **NETWORK redirect layer** (`windivert_network.hpp`, `tcp_redirect.hpp`): filter `ip and outbound and tcp and (!loopback or tcp.SrcPort == redirect_port)` (IPv4 only since v0.13.1; IPv6 stays on the kernel path and goes direct), opened in divert mode (`flags = 0`). A proxied packet is handed to the local acceptor as `AppIP:AppPort -> AppIP:redirect_port`, injected outbound. Only acceptor replies enter the loopback branch; they are restored to `OriginalRemoteIP:OriginalRemotePort -> AppIP:AppPort` and injected inbound on the saved original interface. This avoids fabricating an inbound public-peer stream at the acceptor, which can be aborted by Windows stream filters on physical adapters. Initial undecided SYNs remain **parked**, and both the injector and live workers use the same transformation. Two dedicated blocking worker threads.
- WinDivert's layer split is the reason for both layers: NETWORK can block/inject but has no PID; SOCKET has the PID but cannot touch packets. The local port is the only key they share.

### TCP SYN parking (v0.10)

Why: the kernel emits the SOCKET CONNECT event *before* the SYN (0 violations in 58, lead p50 17.6 µs), but our SOCKET and NETWORK pipelines are two independent async paths of comparable latency. Before parking, the NETWORK worker released a SYN whose port had no decision yet — which for a freshly spawned process (git, curl, gh: connect ~150 ms after birth, ETW announces it 1–2 s later) was *every* first connection. Measured interception rate for fresh `git ls-remote`: **0/30**. The original design record and PoC measurements were kept outside this repository.

How:

1. NETWORK worker sees an outbound `SYN && !ACK` whose slot has no usable decision → copies packet + `WINDIVERT_ADDRESS` into a bounded pool (`syn_parker.hpp`, 256 × 2 KB) and CASes the slot `empty → pending(gen, idx)`. The worker keeps receiving; nothing blocks.
2. SOCKET handler (strand) decides and calls `PortTracker::publish`. If the slot is `pending`, the CAS `pending → proxied|direct` transfers ownership of the pool index to the strand, which hands it to the **injector thread**.
3. Injector copies the packet out, frees the pool slot, then sends: verbatim for `direct`, reflected for `proxied`. (`WinDivertSend` is 47–190 µs; the strand only publishes.)
4. **Watchdog**: the injector wakes every 1 ms (`CreateWaitableTimerEx` + `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`; a plain 1 ms wait is quantised to the 15.6 ms tick) and releases anything parked longer than `watchdog_ms` (20, cap 50) unchanged, pinning the port `abandoned` with the SYN's kernel timestamp. A decision that arrives later for that flow is **rejected** (`late_rejected`) rather than applied mid-flow — reflecting an established direct connection is exactly the breakage this removes. Normal park times are < 1 ms; 4.7 ms was the worst seen under a 300-connection burst with zero watchdog fires.

Rules that keep it correct (numbers are the design-record item ids):

- **Four states** `empty / pending / proxied / direct / abandoned` packed as `{state:8 | gen:24 | idx:32}` in one atomic word; every transition is a CAS, the CAS winner owns the pool index (17, 18, 22). Strand does all publishes and clears; workers only `empty → pending`; the watchdog only `pending → abandoned`.
- **Kernel-timestamp TTL** (21): a SYN acts on a slot's decision only if `SYN.Timestamp − slot.connect_ts ≤ 10 ms` (same QPC clock at both layers); older is treated as empty and parks. One exception: the worker records the ISN of each SYN it handles, and a later SYN with the **same ISN** on the same port is that connection retransmitting (RTO ≥ 1 s, so always past the TTL) — it acts on the held state at once (`retransmit_passed`) instead of parking for T and inflating `released_by_watchdog`. A different ISN on the same port is a new connection and takes the park path; Windows randomises the ISN per connection, so the exception cannot swallow a real new flow.
- **Every CONNECT publishes** (2): resolve failure, not-proxied, CIDR-excluded all publish `direct`. So `pending` has one cause: the event never arrived.
- **Phantom CONNECT** (24): each re-injected SYN produces a second CONNECT for the same flow (`ProcessId = 4`, ~60–880 µs later). `PortTracker::is_echo` (same remote, decision younger than the TTL) drops it before any tree lookup.
- **CLOSE fires at `closesocket()`** (25), before the wire is done. CLOSE clears `direct` / `abandoned` / `pending` (parked SYN dropped, pool slot returned); `proxied` slots are cleared only by relay teardown, which posts `clear_if(port, connect_ts)` to the strand (23) — an unconditional off-strand clear could wipe a newer flow that reused the port after a passive close.
- **Never proxy self** (10): the SOCKET filter no longer excludes our PID (an unobserved self connection would park for the whole watchdog); instead `windivert_socket::decide` returns `direct` for `GetCurrentProcessId()` before consulting any rule, so `*.exe`-style rules cannot loop upstream connections. Only matters for non-loopback proxies — with a `127.0.0.1` proxy `!loopback` already keeps self out.
- **Pool full → pass + pin** (8), never evict; a duplicate SYN while `pending` is dropped without allocating (19). The leak signal is `pool_in_use` not returning to 0 between bursts (12).
- **Kill switch** `tcp_syn_parking.enabled = false` (14): no pool, no injector thread, no synchronous PID resolve, SOCKET publishes only `proxied`, NETWORK passes every undecided SYN — the pre-v0.10 code paths, for when the new code itself is what broke. Resolve and parking are a pair: resolve without parking publishes the decision ~100 µs after the SYN left, mid-flow, and the NETWORK layer then reflects an established direct connection (measured: 20/20 TLS timeouts). Startup-only; logged as `[SYN-PARK] enabled/disabled`.
- **PID recycling at connect time**: ETW STOP is delivered as late as START, so a spawn loop hands a new process a PID whose dead predecessor is still in the tree (seen 1 in 30). `resolve_pid_now` therefore verifies every known PID against the live PSN (one `OpenProcess` + `NtQueryInformationProcess`, ~10–30 µs) and re-resolves on mismatch; the insert tombstones the stale entry and the late STOP becomes a no-op.
- **UDP** (11): per-packet policy table since v0.9.5; since v0.11 the first datagrams of an undecided port are parked too (see "UDP interception").
- Build: `PROXYCLAW_PROJECTION_COALESCE` is now ON (option default + `CMakePresets.json`). `resolve_pid_now` triggers a tree change on the strand; without coalescing that is an immediate full refresh + ~35 KB serialize, which would hold the next CONNECT decisions past the watchdog. If you reuse an old `build/` cache, reconfigure via the preset.

Counters (`GET /api/stats` → `tcp_syn_parking`, and a `[SYN-PARK]` INFO line every 60 s when they change): `parking.released_by_watchdog` and `socket.late_rejected_proxied` are the two that mean "proxy missed a flow"; `parking.pool_in_use` must drop back to 0; `gen_mismatch`, `oversize`, `send_failures` must stay 0.

### PortTracker

- `std::array<TrackerSlot, 65536>`, each slot one 64-byte line: `atomic<uint64_t> word` (state / generation / pool index) + `connect_ts` (kernel timestamp of the CONNECT) + `pinned_ts` (kernel timestamp of the SYN the watchdog released) + `TrackerEntry{remote_addr, remote_port, group_id}` (~4 MB heap)
- `alignas(64)` per slot to avoid false sharing; `TrackerEntry` must stay trivially copyable (static_assert — PR #1's shared_ptr-in-slot was UB)
- Auxiliary fields are written before the release-CAS and read after an acquire load; each state reads only its own aux fields, so a writer that loses its CAS clobbers nothing that matters
- `proxied` entries persist for the connection lifetime and are cleared by the relay via `clear_if` on the strand; `direct` / `abandoned` by the SOCKET CLOSE event; the TTL covers whatever both miss

### C++20 coroutine relay

- `acceptor.hpp`: Asio TCP acceptor spawns `relay_session` coroutine per connection
- `relay.hpp`: bidirectional async pipe using `asio::co_spawn` + `async_read_some` / `async_write`
- `socks5_async.hpp`: SOCKS5 handshake as a coroutine (no blocking threads)

### Rule priority

1. **Manual rule** (PID exact match, sets `flags | MANUAL` on flat_tree entry) — highest
2. **Auto rule** (process name / cmdline match, config order) — sets `group_id`
3. **Default**: DIRECT (`group_id = 0`, no flags)

### Destination policy (v0.10.3)

One verdict, `rule_engine_v3::route_reason()` / `evaluate_destination()` in
`rules/traffic_filter.hpp`, is shared by the TCP SOCKET layer, the UDP SOCKET
layer (connected sockets), the UDP NETWORK layer (per packet, through the
published `PolicyTable`) and the connection list API. Order:

1. `rule.protocol` must cover the transport (auto rules only)
2. `default_exclude_cidrs` (global)
3. `dst_filter.exclude_cidrs`, then `dst_filter.exclude_ports`
4. `dst_filter.include_cidrs` (when non-empty, must match)
5. `dst_filter.include_ports` (when non-empty, must match)

Manual hijacks skip 1 and 3–5. `/api/connections/*` returns the verdict as
`proxy_status` plus `route_reason` (`none`, `global_exclude`, `rule_exclude`,
`rule_exclude_port`, `rule_include_cidr_miss`, `rule_include_port_miss`,
`rule_protocol`). Before v0.10.3 only the CIDR excludes reached the data path,
TCP ignored `protocol`, and the UI evaluated the full filter on its own.

### Auto rule matching

- **`process_name`**: glob match (`*` any sequence, `?` single char, case-insensitive). Examples: `python.exe`, `curl*`
- **`cmdline_pattern`**: two modes, auto-selected by pattern content:
  - **Keyword mode** (no `*` or `?`): space-separated fragments, ALL must appear as case-insensitive substrings, order-independent. `udp_client` matches `python.exe udp_client.py --port 8080`; `udp_client 8080` also matches; `udp_client 9090` does not.
  - **Glob mode** (contains `*` or `?`): full wildcard match against the entire cmdline, order-sensitive. `*udp_client*8080*` matches; `*8080*udp_client*` does not.
- **Lazy cmdline query**: `cmdline` is fetched via `NtQueryInformationProcess` only when a rule has `cmdline_pattern` set AND `process_name` already matched. Cached in `process_entry.cmdline_cache` (sentinel `\x01` = queried but failed/empty). Zero overhead when no rule uses cmdline.

### Process tree logic for auto rules (hack_tree pinned true since v0.9.0)

Find matching process → traverse to tree root (parent not matching same name) → set flags on root and all LC-RS descendants (including dynamically created children via ETW ProcessStart).

Since v0.9.0 the UI exposes only **Hack** and **Unhack** (no separate "Unhack Tree"); both operate in tree mode. The `AutoRule.hack_tree` field is preserved on disk for forward compatibility but `rule_engine_v3::set_auto_rules` pins it to `true` at load time, so a per-rule single-node mode does not exist at runtime. To spare a single descendant the user clicks Unhack on that specific node — clearing manual flags off a subtree leaves siblings unaffected.

The HTTP handler `process_handlers.cpp::handle_hijack` / `handle_unhijack` no longer reads the `tree` body/query parameter; the `process_tree_service` signature still takes `tree_mode` so a future per-rule exclude can plug in.

### PID recycling handling

- Windows recycles PIDs, and ETW delivers `ProcessStop` 1–2 s late (same as `ProcessStart`). Inside that window a new process can carry a PID whose dead owner is still in the tree. A tight spawn loop hits this routinely (measured: 1 in 30 fresh curls, 14 in 200 under a 1000-process storm).
- The tree's identity is `(pid, psn)` (`ProcessSequenceNumber`, boot-unique): `find_by_pid_psn` for ETW STOP and idempotent START; `add_entry` with a known PID and a different PSN tombstones the old entry first. The hot-path `find_by_pid` (SOCKET handlers) returns the latest owner, so `resolve_pid_now` verifies a known PID against the live PSN before trusting it.
- **Rule for any state keyed by a bare PID** (added after the second recycled-PID bug, 2026-09-07): it must say how it survives a recycled PID — either key it by `(pid, psn)` / PSN, or reset it on both owner-change hooks: `process_tree_manager::handle_stop` (ETW STOP) *and* the overwrite path in `handle_start_or_rundown` (a different-PSN insert over an existing PID; reached from ETW START and from the synchronous resolve). Today's bare-PID state: `AutoRule::matched_pids` — reset via `rule_engine_v3::on_process_exit` on both hooks. Per-process rule exclusions (v0.13.1) are keyed by `(pid, psn)` and owned by the engine (`rule_engine_v3::exclusions_`): runtime only, never part of `ConfigV2` (so a config reload cannot copy stale PIDs back), kept across `set_auto_rules` for rule ids that still exist, dropped by `on_process_exit` on both hooks, and validated on every lookup — a recycled PID whose PSN differs is not excluded even if the STOP was lost. Orphans (children whose parent is not in the tree yet) are parked by `(pid, psn)` in `domain::orphan_registry`, never by flat-tree index (`compact()` renumbers); they expire after 10 s (sweep every 30 s and after each lost-event rundown) and the registry is capped at 4096. Known residual: tree inheritance tests `matched_pids.contains(parent_pid)`, so a parent PID recycled inside the window lets an unrelated new process's children inherit the rule until the STOP lands; the systematic fix is PSN-keyed rule state (see the deferred list in the project notes).
- PortTracker slots are not cleaned by ETW at all: `proxied` slots by relay teardown, `direct` / `abandoned` by SOCKET CLOSE, and the kernel-timestamp TTL covers what both miss (see "TCP SYN parking").
- Flat-tree LC-RS pointers are updated on tombstone; children are reparented to the nearest alive ancestor.

### Multi-proxy routing via proxy groups

- `ProxyGroup`: named proxy config with auto-increment `uint32_t id` (0 = default group)
- `AutoRule.proxy_group_id` references a group
- Relay coroutine reads group config from a shared map to determine SOCKS5 target

### UDP interception (mirrors TCP, per-port sessions)

- Same dual-layer architecture as TCP: `windivert_socket_udp` + `windivert_network_udp`. The NETWORK filter is `ip and udp and outbound and !loopback` (IPv4 only); a SOCKET CONNECT to a real IPv6 remote is counted (`ipv6_unmanaged`) and ignored, while BIND stays a per-port decision because a dual-stack socket bound on the IPv6 layer can still send IPv4.
- First-packet parking (v0.11): `UdpPortTracker` slots are empty / direct / proxied. The SOCKET layer writes direct or proxied for every BIND it sees (its own process included) and clears on CLOSE, then calls `windivert_network_udp::release(port)`. A NETWORK worker that meets an empty slot parks the datagram (`udp_first_packet_parker`, 1024 total / 64 per port, decision re-checked under the lock so none is stranded); release sends it per the decision; a watchdog sends anything older than `udp_first_packet.watchdog_ms` (default 20) direct and pins the port direct. Config `udp_first_packet.enabled=false` restores the old behavior.
- Each app-level UDP port gets its own SOCKS5 UDP ASSOCIATE session (RFC 1928)
- **Per-packet addressing** (v0.10.3): the NETWORK worker does not reflect a proxied datagram. It hands `UdpOutbound{app_port, group_id, dst, payload}` to the relay (`UdpOutboundSink::submit`, a non-blocking post onto the relay strand) and consumes the original packet. Each datagram therefore keeps its own destination, so one socket that talks to several peers (DNS to two resolvers, STUN/WebRTC, games, QUIC) no longer has its packets sent to whichever destination was seen last. Before v0.10.3 the destination came from a per-port table entry that every packet overwrote.
- Upstream queues per app port; each port has one `flush_port` coroutine, so a slow SOCKS5 handshake for one socket only delays that socket. Limits (`UdpQueueLimits`): 8192 datagrams / 32 MB in flight overall, 512 per port; excess is dropped and counted (`[UDP-RELAY] Dropped datagram`). If the session cannot be created, that port's queue is dropped instead of paying the handshake timeout per datagram.
- Downstream: the reply is injected with the source address the SOCKS5 UDP header names (the real responder), and only when that address:port is in the socket's peer set (peers it sent to; LRU, 1024 per socket). Other datagrams are dropped (`filtered`), like an address-and-port restricted NAT.
- `UdpSessionTable` (keyed by app port) now holds app-side metadata only for injection (app address, interface, pid, group) plus the most recent destination for the connection list and the DNS 10 s idle rule. Peer sets are dropped by the relay's 30 s cleanup once the route expires.
- Response routing stays per app port — no cross-process bleed
- `UdpTrackerEntry` is `{group_id, pid, policy_id}` — trivially copyable, `policy_id` indexes the published `PolicyTable`
- Dst excludes are evaluated per packet in the NETWORK worker via a `PolicyReader` (one generation compare per packet), for connected and unconnected sockets alike. WFP raises a SOCKET CONNECT event for each new remote an unconnected socket `sendto()`s, not only for `connect()`, so the SOCKET layer cannot tell a socket's only destination from one of many; before v0.10.3 it cleared the tracker slot on an excluded CONNECT, which also sent the socket's other destinations direct.
- The SOCKS5 UDP data socket binds the wildcard address (to reach a remote relay), so downstream drops any datagram whose sender is not the relay endpoint.
- See `src/udp/` for all UDP-specific files

### DNS proxy (optional, off by default)

- User enables via Settings → DNS Proxy toggle
- **Forwarder mode** (only mode implemented): `dns_forwarder` listens UDP on `127.0.0.2:53`, forwards queries to upstream (default `8.8.8.8:53`) via SOCKS5 UDP ASSOCIATE using the first proxy group's endpoint
- `DnsManager` (src/core/dns_manager.hpp) orchestrates:
  - **System DNS auto-config**: on enable, saves original DNS per active IPv4 interface to `dns_state.json`, points interfaces to `127.0.0.2` via `SetInterfaceDnsSettings`
  - **Hot-reload**: Settings UI changes trigger `apply()`, which diffs new vs current config and starts / stops / restarts forwarder + updates system DNS accordingly, no restart required
  - **Crash recovery**: on startup, if `dns_state.json` exists it means the previous session exited abnormally — restore system DNS from file, then delete it
- Limitation: forwarder is UDP-only.
- TCP:53 from a *proxied* process (e.g. Chromium's built-in resolver) is handled by the TCP relay, not the forwarder, whether or not the DNS proxy is enabled: the destination is rewritten to `dns.upstream_host:dns.upstream_port` and sent through the process's proxy group (`proxy/tcp_dns_upstream.hpp`, published by `DnsManager::apply`). The relay speaks SOCKS5 with an IPv4 destination, so when `upstream_host` is not an IPv4 literal (a hostname, IPv6, loopback or `0.0.0.0`) it falls back to `8.8.8.8:53` and logs a warning. Before v0.13.1 this was hardcoded to `8.8.8.8:53`.

## API Endpoints

### Access control (v0.10.2)

The API listens on `127.0.0.1:18080` inside an elevated process, so loopback
binding alone is not a boundary: a page in the user's browser could otherwise
send requests to it. `src/transport/api_auth.hpp` (installed as the httplib
pre-routing handler in `middleware.cpp`) applies three checks to every request:

1. **Host** must be `127.0.0.1:18080` or `localhost:18080` (421 otherwise),
   which defeats DNS rebinding.
2. **Origin**, when present, must be the UI's own origin, or the origin of
   `PROXYCLAW_DEV_URL` in frontend dev mode (403 otherwise).
3. **Session token** on every `/api/` path: a per-launch random value from
   `BCryptGenRandom`, sent as the `proxyclaw_session` cookie (`HttpOnly;
   SameSite=Strict`) or the `X-ProxyClaw-Token` header (401 otherwise).

The host window navigates to `GET /api/session?t=<token>`, which sets the
cookie and redirects to `/`; the token never appears in static assets and is
redacted from the navigation log line. No CORS headers are sent and `OPTIONS`
is no longer answered. WebView2 web messages are accepted only from the origin
the host navigated to. Test harnesses set `PROXYCLAW_API_TOKEN` (32+ chars)
for the process they launch and send the header.
Isolation from other local processes of the same user is out of scope; that
would need an ACL'd named pipe.

### Routes

```
GET    /api/session?t=<token>      - Set the session cookie, redirect to /
GET    /api/processes/:pid         - Single process info
GET    /api/processes/:pid/detail  - Process detail (cmdline, path)
GET    /api/hijack                 - List all hijacked PIDs
POST   /api/hijack/:pid            - Hijack a PID (manual rule); 400 if group_id does not exist
DELETE /api/hijack/:pid            - Unhijack a PID
POST   /api/hijack/batch           - Batch hijack / unhijack; 400 if group_id does not exist (hijack)
GET    /api/tcp                    - TCP connections (optionally ?pid=X)
GET    /api/udp                    - UDP connections
GET    /api/auto-rules             - List auto rules
POST   /api/auto-rules             - Create auto rule
PUT    /api/auto-rules/:id         - Update auto rule
DELETE /api/auto-rules/:id         - Delete auto rule
POST   /api/auto-rules/:id/exclude/:pid - Exclude a running process from an auto rule (runtime only, keyed by pid+psn; 404 if rule or process missing)
DELETE /api/auto-rules/:id/exclude/:pid - Remove PID exclusion
GET    /api/proxy-groups           - List proxy groups
POST   /api/proxy-groups           - Create proxy group (400: port not 1-65535, empty host or host:port, type != socks5, non-empty user/password)
PUT    /api/proxy-groups/:id       - Update proxy group (same validation)
DELETE /api/proxy-groups/:id       - Delete proxy group
POST   /api/proxy-groups/:id/migrate - Migrate rules from one group to another before delete
POST   /api/proxy-groups/:id/test  - Measure latency to test_url
GET    /api/config                 - Get full config JSON
PUT    /api/config                 - Save full config JSON (proxy_groups validated as above)
GET    /api/stats                  - Counts (hijacked_pids, auto_rules_count, tree_ready, process_count, ipv6_unmanaged {tcp, udp}, tcp_syn_parking)
GET    /api/env                    - Environment info
POST   /api/shell/browse-exe       - Open file dialog for .exe
POST   /api/shell/reveal           - Reveal file in Explorer
```

The engine is always-on while `proxyclaw.exe` runs — there is no start/stop control plane. WinDivert layers + acceptor + UDP relay + DNS manager are initialized at startup and torn down on shutdown.

Push events (delivered via `WM_PUSH_TO_FRONTEND` → `PostWebMessageAsJson`,
*not* over HTTP — see "Backend → frontend push" above):
- `process_update` — full process-tree snapshot, after the projection's
  100 ms coalesce window
- `auto_rule_changed` — `{action: string}`; tells the frontend to refetch
  rules-related state

## Config Schema (`proxyclaw.json`)

```json
{
  "version": 2,
  "default_proxy": { "type": "socks5", "host": "127.0.0.1", "port": 7890 },
  "proxy_groups": [
    {
      "id": 0,
      "name": "default",
      "host": "127.0.0.1",
      "port": 7890,
      "type": "socks5",
      "test_url": "http://www.gstatic.com/generate_204"
    }
  ],
  "next_group_id": 1,
  "default_exclude_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"],
  "auto_rules": [
    {
      "id": "...",
      "name": "...",
      "enabled": false,
      "process_name": "curl*",
      "cmdline_pattern": "",
      "image_path_pattern": "",
      "hack_tree": true,
      "protocol": "tcp",
      "proxy_group_id": 0,
      "dst_filter": {}
    }
  ],
  "ui": { "window_width": 1200, "window_height": 800, "dark_mode": true, "close_to_tray": true },
  "io_threads": 0,
  "log_level": "info",
  "dns": {
    "enabled": false,
    "mode": "forwarder",
    "upstream_host": "8.8.8.8",
    "upstream_port": 53,
    "listen_host": "127.0.0.2",
    "listen_port": 53
  },
  "tcp_syn_parking": { "enabled": true, "watchdog_ms": 20, "pool_size": 256 }
}
```

`tcp_syn_parking` is read at startup only. `enabled: false` is the kill switch (see "TCP SYN parking"); `watchdog_ms` is clamped to 5–50 and `pool_size` to 32–4096.

## Build

- **Configure**: `python scripts/prepare_release_deps.py`, then `cmake --preset windows` (VS 2022) or `cmake --preset windows-vs2026` (uses `CMakePresets.json`)
- **Build Release**: `cmake --build build --config Release`
- **Build Debug**: `cmake --build build --config Debug`
- **Unit tests**: `ctest --test-dir build -C Release --output-on-failure` (api_auth, dns_wire, dns_manager, ui_config, config_migration, log_tail, projection, tcp_redirect, runtime_state)
- **Run** (admin required): `.\build\Release\proxyclaw.exe`
- **Frontend dev**: `cd frontend && npm run dev`, then start proxyclaw.exe with `PROXYCLAW_DEV_URL=http://localhost:5173` (the window enters through `/api/session`, proxied by Vite)
- **Frontend unit tests**: `cd frontend && npm test` (Vitest)
- **Frontend build**: `cd frontend && npm run build`
- **Opt-in: refresh-coalesce window** (perf experimentation only, default OFF):
  `cmake -DPROXYCLAW_PROJECTION_COALESCE=ON build` then rebuild. Enables a 100 ms
  refresh-coalesce timer for `batched` urgency events (see "Coalescing" in
  Key Architectural Decisions).

### Resource path resolution (v0.9.0)

Earlier versions resolved `proxyclaw.log`, `proxyclaw.json`, `dns_state.json`, and `frontend/dist` against the launching shell's cwd, which silently broke when running under Task Scheduler (cwd = `system32`), via shortcut, or from a parent directory. v0.9.0 makes resolution explicit and cwd-independent:

- **`src/core/exe_paths.hpp`** — small header exposing `exe_path()` / `exe_directory()` / `exe_relative(name)`. All four resources go through these.
- **`proxyclaw.log`** — written to `exe_directory() / "proxyclaw.log"` (set in `main.cpp::setup_logger`).
- **`proxyclaw.json`** — `--config <path>` if explicitly passed, otherwise `exe_directory() / "proxyclaw.json"`. Wired in `app::app(...)` ctor's initializer list.
- **`dns_state.json`** — `dns_manager` constructor receives `exe_relative("dns_state.json")` from `app::app`.
- **`frontend/dist`** — `http_api_server::setup_static_files` candidate list anchors to `get_executable_dir()` (release zip layout: `<exe>/frontend/dist`; dev build layout: `<exe>/../../frontend/dist`); cwd-relative candidates were removed.

One deliberate exception (v0.9.6): the **WebView2 user data folder** — pure browser cache, not configuration — lives in `%LOCALAPPDATA%\clew\webview_data` (`exe_paths.hpp::local_app_data_directory`, falling back to the old exe-relative `proxyclaw_webview_data` only if `%LOCALAPPDATA%` cannot be resolved). It cannot be exe-relative: when the app is installed under `Program Files`, WebView2's sandboxed child processes cannot use a user data folder inside the install directory and controller creation fails with `0x800700aa` (issue #5, reproduced and variable-isolated 2026-08-31).

The autostart Task Scheduler entry pins `--config <abs path>` explicitly so a system32-cwd launch still finds the user's config. `--minimized` is also part of the registered command line when "Start minimized to tray" is on.

## Build notes

- WinDivert + `SetInterfaceDnsSettings` both require administrator privileges. The UAC manifest is embedded via linker `/MANIFESTUAC:level='requireAdministrator'` (see `CMakeLists.txt`) — double-click triggers UAC prompt automatically.
- ~30 translation units after the three-layer refactor (was a single TU in the legacy header-only layout). `CMakeLists.txt` enables `/MP` for parallel compilation; first clean build is noticeably longer than the legacy version, incremental builds are fine.
- Frontend builds to static files served by cpp-httplib at runtime; dev mode uses Vite's proxy to port 18080.
- Kill `proxyclaw.exe` before rebuilding (MSVC LNK1104 error otherwise).
- `python scripts/verify.py` runs the frontend unit tests and build, the native build, `ctest`, the layering checks (`scripts/check_layering.py`, also run in CI), and the real-WinDivert e2e suites (`tests/e2e_rule_policy.py`, `tests/e2e_api_test.py`), each stage with its own timeout. The e2e stage needs an administrator shell; `--no-e2e` skips it. `--stress` adds the bounded stress smoke (`tests/stress_backend.py --ci`).

### E2E testing in CI

`.github/workflows/release.yml` runs, on every push and PR to `main`:

- `ctest` — all native unit tests;
- `tests/run_proxy_health_tests.py` and `tests/run_dns_network_tests.py` — the
  loopback harnesses (SOCKS5 relay, UDP cleanup, DNS forwarder);
- `tests/e2e_rule_policy.py` — launches the built `proxyclaw.exe` with the real
  WinDivert driver and judges rules, UDP per-packet addressing and the staged
  speed test by what actually leaves the machine;
- `tests/ui_webview2_screenshots.py` — opens the packaged app in a real
  WebView2 window over CDP, fails on any console / page error, and uploads the
  `ui-screenshots` artifact used by the README;
- `tests/e2e_api_test.py --exe <packaged proxyclaw.exe>` — the management API
  suite. It starts the packaged app with a throwaway config whose default group
  is a recording SOCKS5 server, so "went via the proxy" is judged by that
  server seeing the CONNECT rather than by a second exit IP. Also scans
  `proxyclaw.log` for the batch-notify and DELETE-latency invariants, and
  toggles the DNS proxy (system DNS is restored afterwards);
- `tests/stress_backend.py --ci --duration 45` — a bounded smoke on the packaged
  app: `stress_etw.py` process churn (target 40, 1–3 s lifetimes), hijack /
  unhijack every 0.5 s and 4 threads of concurrent GETs, with proxyclaw.exe
  working set / private bytes / handles sampled each second. It fails only on
  request errors, a proxyclaw crash or a dead API afterwards; latency and memory
  are reported, not gated (a shared runner is too noisy for thresholds). The
  JSON summary and console output are uploaded as the `stress-summary` artifact.

The Playwright push tests and HTTP log-scan helpers that predate the React
frontend remain local-only history; the longer stress scenarios
(`--scenario steady`, `--visibility-cycle`) are local tools.

