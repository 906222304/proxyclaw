# Changelog

## v0.10.3 (unreleased)

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

### Tests

- New `route_policy_tests` under CTest.

## v0.10.2 (unreleased)

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
