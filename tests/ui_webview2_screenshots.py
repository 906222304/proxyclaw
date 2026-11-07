"""Real-window screenshot test for the WebView2 build of proxyclaw.exe.

Launches proxyclaw.exe with a throwaway config and
WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<port> (the host
merges that env var into its own browser arguments, see
src/ui/webview_app.hpp), attaches Playwright over CDP to the app's own page and
screenshots every tab, the rule editor, the raw JSON editor, the log viewer and
both themes. Console errors and page errors fail the run.

    python tests/ui_webview2_screenshots.py --exe dist/<pkg>/proxyclaw.exe --out build/ui-screenshots

Needs: pip install playwright (no browser download: connect_over_cdp only).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright, expect

# GitHub's windows-2025 runner desktop is 1024x768; the host clamps the window
# to the work area (1024x720 with the taskbar), so ask for exactly that.
WIDTH, HEIGHT = 1024, 720


def wait_cdp(port: int, proc: subprocess.Popen, timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2) as r:
                json.load(r)
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"WebView2 CDP endpoint on :{port} did not come up in {timeout}s")


def wait_app_target(port: int, proc: subprocess.Popen, timeout: float = 60) -> None:
    """Wait until the WebView navigated to the app before attaching Playwright:
    attaching while the target is still about:blank leaves Playwright with a
    stale about:blank page after WebView2 swaps renderers on navigation."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as r:
                targets = json.load(r)
            if any(t.get("type") == "page" and t.get("url", "").startswith("http://127.0.0.1")
                   and "/api/session" not in t.get("url", "") for t in targets):
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"WebView2 never navigated to the app within {timeout}s")


def find_app_page(browser, timeout: float = 30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ctx in browser.contexts:
            for page in ctx.pages:
                if page.url.startswith(("http://127.0.0.1", "http://localhost")):
                    return page
        time.sleep(0.5)
    urls = [p.url for c in browser.contexts for p in c.pages]
    raise RuntimeError(f"app page not found among CDP targets: {urls}")


TARGET_EXE = "pc-shot-target.exe"


def wait_tree_ready(token: str, proc: subprocess.Popen, timeout: float = 60) -> int:
    """Wait for the backend to report its initial process rundown verified
    against the OS process list (/api/stats tree_ready) and return its
    process count. Run 42180806121 attempt 1 showed a tree stuck at 20 of
    ~150 processes for the whole session (rundown dropped at startup); the
    backend now detects and repairs that, and this makes the harness wait
    for it instead of screenshotting a partial tree."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
        try:
            req = urllib.request.Request("http://127.0.0.1:18080/api/stats",
                                         headers={"X-ProxyClaw-Token": token})
            with urllib.request.urlopen(req, timeout=3) as r:
                last = json.load(r)
            if last.get("tree_ready", True):
                return int(last.get("process_count") or 0)
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"backend process tree not ready within {timeout}s: {last}")


def main() -> int:
    # The runner console is cp1252; Playwright errors quote Chinese locators.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--port", type=int, default=9222)
    args = ap.parse_args()

    exe = args.exe.resolve()
    out = args.out.resolve()
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_ui_shots_"))
    token = secrets.token_hex(32)

    config = {
        "version": 2,
        "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": 7890},
        "proxy_groups": [
            {"id": 0, "name": "default", "host": "127.0.0.1", "port": 7890,
             "type": "socks5", "test_url": "http://1.1.1.1/"},
            {"id": 1, "name": "香港节点", "host": "hk.example.invalid", "port": 1080,
             "type": "socks5", "test_url": "https://1.1.1.1/"},
        ],
        "next_group_id": 2,
        "auto_rules": [
            {"id": "ui-shot-1", "name": "Chrome via proxy", "enabled": True,
             "process_name": "chrome.exe", "proxy_group_id": 0},
            {"id": "ui-shot-2", "name": "Python direct", "enabled": False,
             "process_name": "python.exe", "proxy_group_id": 1},
            # Matches only the idle helper spawned below (a renamed ping.exe:
            # ICMP only, so proxying it changes nothing) for the
            # per-process exclude screenshots.
            {"id": "ui-shot-3", "name": "Exclude demo", "enabled": True,
             "process_name": TARGET_EXE, "proxy_group_id": 0},
        ],
        "log_level": "info",
        "dns": {"enabled": False},
        "ui": {"window_width": WIDTH, "window_height": HEIGHT,
               "close_to_tray": False, "dark_mode": True},
    }
    cfg_path = work / "proxyclaw.json"
    cfg_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

    env = dict(os.environ, PROXYCLAW_API_TOKEN=token,
               WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=f"--remote-debugging-port={args.port}")
    # Long-lived helper process the "Exclude demo" rule matches.
    target = None
    try:
        target_exe = work / TARGET_EXE
        shutil.copy2(pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "PING.EXE", target_exe)
        target = subprocess.Popen([str(target_exe), "-n", "900", "127.0.0.1"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        print(f"(exclude demo target not started: {e})")
    proc = subprocess.Popen([str(exe), "--dev-hooks", "--config", str(cfg_path)], cwd=exe.parent, env=env)

    console: list[str] = []
    problems: list[str] = []
    shots: list[str] = []
    rc = 1
    close_requested = False
    try:
        wait_cdp(args.port, proc)
        wait_app_target(args.port, proc)
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{args.port}")
            page = find_app_page(browser)

            def on_console(msg):
                line = f"[{msg.type}] {msg.text}"
                loc = msg.location or {}
                if loc.get("url"):
                    line += f"  ({loc.get('url', '').split('?')[0]}:{loc.get('lineNumber')})"
                console.append(line)
                if msg.type == "error":
                    problems.append("console error: " + line)

            def on_pageerror(err):
                console.append(f"[pageerror] {err.stack or err}")
                problems.append(f"page error: {err}")

            page.on("console", on_console)
            page.on("pageerror", on_pageerror)
            # Reload so console output from the very first render is captured.
            # The URL carries the session token, so a reload keeps auth.
            page.reload(wait_until="load")

            vp = page.evaluate("[innerWidth, innerHeight, devicePixelRatio]")
            console.append(f"[info] viewport {vp}")
            print(f"viewport (real window client area): {vp}")

            page.wait_for_function("document.querySelector('#root')?.childElementCount > 0", timeout=30000)
            page.get_by_role("tablist", name="主导航").wait_for(timeout=30000)
            # The title-bar status chip (● 18080) replaced the footer.
            page.locator('[data-connected="true"]').wait_for(timeout=30000)
            # Process tree data arrives over the WebView2 push channel after the
            # ready handshake; wait until at least one process row is shown.
            page.locator("[data-depth]").first.wait_for(timeout=30000)
            # The first push can predate the end of the initial rundown. Wait
            # for the backend to verify its tree, then for the UI to show (at
            # least most of) it and stop changing, so every screenshot below
            # sees the full tree including proxyclaw.exe itself.
            backend_count = wait_tree_ready(token, proc)
            want = max(1, int(backend_count * 0.7))
            page.wait_for_function(
                f"Number(document.querySelector('[data-testid=process-count]')?.textContent) >= {want}",
                timeout=30000)
            settle_start = stable_since = time.time()
            prev = None
            while time.time() - stable_since < 1.5:
                cur = page.evaluate("document.querySelector('[data-testid=process-count]')?.textContent")
                if cur != prev:
                    stable_since, prev = time.time(), cur
                if time.time() - settle_start > 20:  # churn never settles: go on
                    break
                page.wait_for_timeout(250)
            count = page.evaluate("document.querySelector('[data-testid=process-count]')?.textContent")
            console.append(f"[info] process count {count}")
            print(f"process count: {count}")
            page.wait_for_timeout(1000)

            def shot(name: str) -> None:
                page.wait_for_timeout(400)
                path = out / f"{len(shots) + 1:02d}-{name}.png"
                page.screenshot(path=str(path))
                shots.append(path.name)
                print(f"saved {path.name}")

            def set_dark(want: bool) -> None:
                if page.evaluate("document.documentElement.classList.contains('dark')") != want:
                    page.get_by_title("切换主题").click()
                page.wait_for_function(
                    f"document.documentElement.classList.contains('dark') === {str(want).lower()}")

            def tab(name: str) -> None:
                page.get_by_role("tab", name=re.compile("^" + name)).click()
                expect(page.get_by_role("tab", name=re.compile("^" + name))).to_have_attribute(
                    "data-state", "active")

            def close_dialog() -> None:
                page.get_by_role("dialog").get_by_role("button", name="关闭", exact=True).first.click()
                expect(page.get_by_role("dialog")).to_have_count(0)

            def close_json_editor() -> None:
                # The config editor replaces the settings page inline (not a dialog).
                page.get_by_role("button", name="关闭", exact=True).last.click()
                expect(page.locator(".cm-editor")).to_have_count(0)

            set_dark(True)
            tab("网络")
            shot("network-dark")
            # Select a process (prefer proxyclaw itself) for the per-process view.
            page.get_by_placeholder("搜索 PID 或进程名称…").fill("proxyclaw")
            # The process tree precedes the connections table in DOM order.
            pc_row = page.locator('[data-depth] span[title="proxyclaw.exe"]').first
            pc_row.wait_for(state="visible", timeout=30000)
            pc_row.click(timeout=30000)
            page.wait_for_timeout(1500)
            # Playwright scrolls the clicked (deeply indented) row into view
            # horizontally; a mouse user would not, so undo that.
            page.evaluate("document.querySelectorAll('*').forEach(e => { if (e.scrollLeft) e.scrollLeft = 0 })")
            # The selected row is deeply nested; with the indent cap its name
            # must still fit the sidebar without being cut off.
            fit = page.evaluate("""() => {
                const el = [...document.querySelectorAll('span[title="proxyclaw.exe"]')][0]
                const row = el?.closest('[data-depth]')
                return el ? { depth: Number(row?.dataset.depth), scroll: el.scrollWidth, client: el.clientWidth } : null
            }""")
            console.append(f"[info] selected tree row {fit}")
            print(f"selected tree row: {fit}")
            if not fit or fit["scroll"] > fit["client"] + 1:
                problems.append(f"process tree name truncated: {fit}")
            # The header path middle-truncates; the exe name must stay visible.
            path_fit = page.evaluate("""() => {
                const box = document.querySelector('[data-testid=process-path]')
                const exe = box?.querySelector(':scope > .shrink-0')
                if (!box || !exe) return null
                const b = box.getBoundingClientRect(), e = exe.getBoundingClientRect()
                return { exe: exe.textContent, inside: e.right <= b.right + 1 && e.width > 0 }
            }""")
            console.append(f"[info] header path {path_fit}")
            if not path_fit or not path_fit["inside"]:
                problems.append(f"header exe name clipped: {path_fit}")
            shot("network-selected-process-dark")

            # Per-process exclude: an auto-proxied process offers 此进程不走代理
            # in the header ⋯ menu; afterwards it shows 已排除 and offers 恢复代理.
            if target is not None:
                page.get_by_placeholder("搜索 PID 或进程名称…").fill(TARGET_EXE.removesuffix(".exe"))
                page.wait_for_timeout(500)
                page.locator(f'[data-depth] span[title="{TARGET_EXE}"]').first.click(timeout=60000)
                page.wait_for_timeout(1000)
                menu = page.get_by_role("button", name="进程操作")
                menu.click(timeout=30000)
                item = page.get_by_role("menuitem", name=re.compile("此进程不走代理"))
                item.wait_for(timeout=10000)
                shot("network-process-exclude-menu-dark")
                item.click()
                header_badge = page.locator('[data-testid="excluded-badge"]')
                expect(header_badge.first).to_be_visible(timeout=15000)
                expect(page.locator('[data-testid="excluded-dot"]').first).to_be_visible(timeout=15000)
                page.wait_for_timeout(600)
                shot("network-process-excluded-dark")
                menu.click()
                page.get_by_role("menuitem", name="恢复代理").click(timeout=10000)
                expect(header_badge).to_have_count(0, timeout=15000)
                page.keyboard.press("Escape")
            page.get_by_placeholder("搜索 PID 或进程名称…").fill("")
            page.get_by_role("button", name=re.compile("^全部进程")).first.click()
            page.evaluate("document.querySelectorAll('*').forEach(e => { if (e.scrollLeft) e.scrollLeft = 0 })")

            tab("规则")
            page.get_by_text("Chrome via proxy").first.wait_for()
            shot("rules-dark")
            page.get_by_role("button", name="添加规则").click()
            page.get_by_text("自动规则编辑器", exact=True).wait_for()
            shot("rule-editor-new-dark")
            close_dialog()
            page.get_by_role("button", name="编辑规则").first.click()
            page.get_by_text("自动规则编辑器", exact=True).wait_for()
            shot("rule-editor-edit-dark")
            close_dialog()

            tab("代理")
            page.get_by_text("香港节点").first.wait_for()
            shot("proxies-dark")
            # Rows expand inline (test URL, last result, rules).
            page.get_by_text("香港节点").first.click()
            shot("proxies-expanded-dark")
            page.get_by_text("香港节点").first.click()
            page.get_by_role("button", name="新建代理组", exact=True).click()
            page.get_by_role("dialog").wait_for()
            shot("proxy-group-dialog-dark")
            close_dialog()

            tab("设置")
            page.get_by_role("switch", name="关闭窗口后保持后台运行", exact=True).wait_for()
            shot("settings-dark")
            page.get_by_role("button", name="查看日志", exact=True).click()
            page.get_by_role("dialog").wait_for()
            page.wait_for_timeout(1500)
            shot("log-viewer-dark")
            close_dialog()
            page.get_by_role("button", name="编辑", exact=True).click()
            page.locator(".cm-editor").wait_for(timeout=20000)
            shot("json-editor-dark")
            close_json_editor()

            set_dark(False)
            tab("网络")
            shot("network-light")
            tab("规则")
            shot("rules-light")
            page.get_by_role("button", name="编辑规则").first.click()
            page.get_by_text("自动规则编辑器", exact=True).wait_for()
            shot("rule-editor-edit-light")
            close_dialog()
            tab("代理")
            shot("proxies-light")
            tab("设置")
            shot("settings-light")
            page.get_by_role("button", name="编辑", exact=True).click()
            page.locator(".cm-editor").wait_for(timeout=20000)
            shot("json-editor-light")
            close_json_editor()
            set_dark(True)
            tab("网络")

            if problems:
                print("FAIL: console/page errors:\n  " + "\n  ".join(problems))
            else:
                rc = 0
                print(f"PASS {len(shots)} screenshots, no console errors / page errors")

            # Close the window the way the title-bar X does; close_to_tray is
            # off in this config, so the app exits.
            close_requested = True
            try:
                page.evaluate("window.chrome.webview.postMessage('close')")
            except Exception as e:  # page goes away while evaluating
                print(f"(close evaluate: {e.__class__.__name__})")
            try:
                browser.close()
            except Exception:
                pass
    except Exception as e:  # noqa: BLE001
        problems.append(f"harness: {e!r}")
        print(f"FAIL harness: {e!r}")
        rc = 1
    finally:
        if target is not None and target.poll() is None:
            target.kill()
        if not close_requested and proc.poll() is None:
            proc.terminate()
        try:
            code = proc.wait(20)
            print(f"proxyclaw.exe exited with code {code}")
            if close_requested and code != 0 and rc == 0:
                print("FAIL: non-zero exit code")
                rc = 1
        except subprocess.TimeoutExpired:
            print("FAIL: proxyclaw.exe did not exit within 20s after close; killing")
            proc.kill()
            rc = 1
        (out / "console.log").write_text("\n".join(console) + "\n", encoding="utf-8")
        log = exe.parent / "proxyclaw.log"
        if log.exists():
            shutil.copy2(log, out / "proxyclaw.log")
        shutil.rmtree(work, ignore_errors=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
