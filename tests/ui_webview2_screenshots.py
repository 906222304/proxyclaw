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


def main() -> int:
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
    proc = subprocess.Popen([str(exe), "--config", str(cfg_path)], cwd=exe.parent, env=env)

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
                # A process without an extractable icon answers /api/icon with
                # 404 by design; the <img> onError swaps in a generic icon.
                # Chromium still logs the failed load as a console error.
                if (msg.type == "error" and "/api/icon" in loc.get("url", "")
                        and msg.text.startswith("Failed to load resource") and "404" in msg.text):
                    console.append("[allowed] " + line)
                    return
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
            page.locator("footer").get_by_text("已连接", exact=True).wait_for(timeout=30000)
            # Process tree data arrives over the WebView2 push channel after the
            # ready handshake; wait until at least one process row is shown.
            page.get_by_text(re.compile(r"\.exe$", re.I)).first.wait_for(timeout=30000)
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

            set_dark(True)
            tab("网络活动")
            shot("network-dark")
            # Select a process (prefer proxyclaw itself) for the per-process view.
            row = page.get_by_text("proxyclaw.exe", exact=True)
            if row.count() == 0:
                row = page.get_by_text(re.compile(r"\.exe$", re.I))
            row.first.click()
            shot("network-selected-process-dark")

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
            close_dialog()

            set_dark(False)
            tab("网络活动")
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
            close_dialog()
            set_dark(True)
            tab("网络活动")

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
