# Changelog

## v0.11.0 (unreleased)

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
