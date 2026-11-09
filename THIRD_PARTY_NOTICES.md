# Third-Party Notices

ProxyClaw is released under the MIT License (see [LICENSE](LICENSE)). It bundles or dynamically loads third-party components listed below, each under its own license.

ProxyClaw is derived from Clew v0.10.0 by ymonster: <https://github.com/ymonster/clew-proxy>. The original MIT copyright notice is retained in LICENSE.

## Runtime dependencies shipped with the release

### WinDivert

- Source: <https://github.com/basil00/Divert>
- License: LGPL v3 (or GPL v2 at the user's choice)
- Usage: `WinDivert.dll` + `WinDivert64.sys` are shipped in the release zip and loaded at runtime.
- Original license text: [`WinDivert-2.2.2-A/LICENSE`](WinDivert-2.2.2-A/LICENSE)

## Statically linked C++ libraries

All linked at build time via vcpkg. Their licenses are permissive (MIT / BSL-1.0 / BSD) and compatible with MIT.

| Library | License | Link |
|---|---|---|
| quill | MIT | <https://github.com/odygrd/quill> |
| nlohmann/json | MIT | <https://github.com/nlohmann/json> |
| cpp-httplib | MIT | <https://github.com/yhirose/cpp-httplib> |
| asio (standalone) | Boost Software License 1.0 | <https://think-async.com/Asio/> |

## WebView2 Runtime

- Provided by Microsoft, loaded at runtime from the system-installed WebView2 Runtime.
- License: Microsoft Software License Terms — see <https://developer.microsoft.com/microsoft-edge/webview2/>

## Frontend dependencies (bundled into `frontend/dist/`)

| Library | License | Link |
|---|---|---|
| React / React DOM | MIT | <https://react.dev/> |
| Vite | MIT | <https://vitejs.dev/> |
| TanStack Query | MIT | <https://tanstack.com/query> |
| TanStack Virtual | MIT | <https://tanstack.com/virtual> |
| Radix UI Primitives | MIT | <https://www.radix-ui.com/> |
| Tailwind CSS | MIT | <https://tailwindcss.com/> |
| tailwind-merge | MIT | <https://github.com/dcastil/tailwind-merge> |
| clsx | MIT | <https://github.com/lukeed/clsx> |
| CodeMirror 6 (incl. Lezer) | MIT | <https://codemirror.net/> |
| React Hook Form (+ resolvers) | MIT | <https://react-hook-form.com/> |
| Zod | MIT | <https://zod.dev/> |
| Sonner | MIT | <https://sonner.emilkowal.ski/> |
| Lucide | ISC | <https://lucide.dev/> |

Full transitive license information is available via `npm ls` / `npx license-checker` in `frontend/`.
