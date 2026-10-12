"""Real built Vue UI in isolated Edge; no real clipboard, shell or proxy writes."""
from pathlib import Path
import json
import os
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/ui-toolchain'))
from playwright.sync_api import sync_playwright, expect

BASE = os.environ['PROXYCLAW_UI_TEST_URL']
output = ROOT / 'build/ui-preview'
output.mkdir(exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', headless=True)
    page = browser.new_page(viewport={'width': 1200, 'height': 850})
    failures, requests, reveals = [], [], []
    page.on('pageerror', lambda error: failures.append(str(error)))
    page.on('request', lambda request: requests.append(request.url))
    page.on('request', lambda request: reveals.append(request.post_data_json) if request.url.endswith('/api/shell/reveal') else None)
    page.add_init_script('''
      Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => { window.copiedLog = text; }}});
    ''')
    page.goto(BASE, wait_until='networkidle')
    page.locator('nav').get_by_role('button', name='设置', exact=True).click()
    expect(page.get_by_role('link', name='本项目源码')).to_have_attribute('href', 'https://github.com/906222304/proxyclaw')
    assert page.get_by_text('基于 Clew', exact=False).count() == 0
    assert not any('monacoRuntime-' in url for url in requests), 'log entry eagerly loaded Monaco'
    page.get_by_role('button', name='查看日志', exact=True).click()
    dialog = page.get_by_role('dialog', name='运行日志')
    pane = dialog.get_by_label('日志内容', exact=True)
    expect(pane).to_contain_text('连接正常')
    expect(pane).to_contain_text('握手超时')
    dialog.get_by_label('日志筛选', exact=True).select_option('problems')
    expect(pane).not_to_contain_text('连接正常')
    expect(pane).to_contain_text('TCP control connection lost')
    dialog.get_by_label('搜索日志', exact=True).fill('握手')
    expect(pane).not_to_contain_text('TCP control connection lost')
    dialog.get_by_role('button', name='复制日志', exact=True).click()
    page.wait_for_function("window.copiedLog?.includes('握手超时')")
    assert page.evaluate('window.copiedLog') == pane.inner_text()
    dialog.get_by_role('button', name='打开文件位置', exact=True).click()
    page.wait_for_timeout(100)
    assert reveals[-1]['path'] == 'C:\\ProxyClaw\\proxyclaw.log'
    dialog.get_by_label('搜索日志', exact=True).fill('')
    dialog.get_by_label('日志筛选', exact=True).select_option('all')
    dialog.get_by_role('checkbox', name='自动刷新', exact=True).uncheck()
    page.wait_for_timeout(200)
    count = requests.count(BASE + '/api/logs')
    page.wait_for_timeout(3300)
    assert requests.count(BASE + '/api/logs') == count, 'manual mode kept requesting'
    dialog.get_by_role('button', name='刷新', exact=True).click()
    page.wait_for_timeout(200)
    assert requests.count(BASE + '/api/logs') == count + 1
    page.screenshot(path=str(output / 'logs.png'))
    dialog.get_by_role('checkbox', name='自动刷新', exact=True).check()
    page.wait_for_timeout(200)
    count = requests.count(BASE + '/api/logs')
    page.wait_for_timeout(3300)
    assert requests.count(BASE + '/api/logs') == count + 1
    dialog.get_by_role('button', name='关闭', exact=True).click()
    expect(dialog).not_to_be_visible()
    count = requests.count(BASE + '/api/logs')
    page.wait_for_timeout(3300)
    assert requests.count(BASE + '/api/logs') == count, 'closed viewer kept polling'

    # Failure/retry and raw text rendering use synthetic data only.
    state = {'status': 500, 'text': '', 'exists': True}
    def respond(route):
        body = {'error': '测试读取失败'} if state['status'] == 500 else {
            'path': 'C:\\ProxyClaw\\proxyclaw.log', 'text': state['text'], 'exists': state['exists'], 'truncated': True}
        route.fulfill(status=state['status'], content_type='application/json', body=json.dumps(body, ensure_ascii=False))
    page.route('**/api/logs', respond)
    page.get_by_role('button', name='查看日志', exact=True).click()
    expect(dialog.get_by_role('alert')).to_contain_text('测试读取失败')
    state.update(status=200, text='<img src=x onerror=alert(1)>\n2026-10-09 14:00:00.000 [E] 新日志')
    dialog.get_by_role('button', name='刷新', exact=True).click()
    expect(pane).to_contain_text('<img src=x onerror=alert(1)>')
    assert dialog.locator('img').count() == 0, 'log text interpreted as HTML'
    expect(dialog.get_by_role('alert')).not_to_be_visible()
    state.update(text='', exists=False)
    dialog.get_by_role('button', name='刷新', exact=True).click()
    expect(pane).to_have_text('日志文件尚未生成。')
    state.update(text='latest log', exists=True)
    # Synthetic visibility changes exercise suspension without hiding a real app.
    page.evaluate('''() => {
      window.testHidden = true;
      Object.defineProperty(document, 'hidden', {configurable: true, get: () => window.testHidden});
      document.dispatchEvent(new Event('visibilitychange'));
    }''')
    count = requests.count(BASE + '/api/logs')
    page.wait_for_timeout(3300)
    assert requests.count(BASE + '/api/logs') == count, 'hidden viewer kept polling'
    page.evaluate("window.testHidden = false; document.dispatchEvent(new Event('visibilitychange'))")
    expect(pane).to_have_text('latest log')
    dialog.get_by_role('button', name='关闭', exact=True).click()
    expect(dialog).not_to_be_visible()
    page.wait_for_timeout(250)
    page.get_by_title('切换主题', exact=True).click()
    page.get_by_role('link', name='本项目源码').scroll_into_view_if_needed()
    page.screenshot(path=str(output / 'settings-logs-about.png'))
    assert not failures, failures
    print('PASS log viewer: repository, search/filter, copy, file location, refresh, close/hidden suspension, retry, missing file, safe text; no UI errors')
    browser.close()
