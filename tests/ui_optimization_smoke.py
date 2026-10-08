from pathlib import Path
import sys
import re
import os
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/ui-toolchain'))
from playwright.sync_api import sync_playwright, expect

BASE = os.environ.get('PROXYCLAW_UI_TEST_URL', 'http://127.0.0.1:23641')
output = ROOT / 'build/ui-preview'
output.mkdir(exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', headless=True)
    page = browser.new_page(viewport={'width': 1200, 'height': 800}, device_scale_factor=1)
    errors = []
    resources = []
    page.on('request', lambda request: resources.append(request.url))
    page.on('pageerror', lambda error: errors.append(error.stack or str(error)))
    page.add_init_script('''
      window.chrome = window.chrome || {};
      window.chrome.webview = {
        addEventListener: (type, listener) => { window.previewListener = listener; },
        postMessage: (message) => {
          if (message?.type === 'ready') setTimeout(() => window.previewListener?.({data: {
            event: 'process_update', data: [{pid:4321,parent_pid:1,name:'ChatGPT.exe',hijacked:true,hijack_source:'auto',children:[]}]
          }}), 50);
          else window.previewCommand = message;
        }
      };
    ''')
    page.goto(BASE, wait_until='networkidle')
    assert page.locator('html').get_attribute('lang') == 'zh-CN'
    expect(page.get_by_role('img', name='ProxyClaw', exact=True)).to_be_visible()
    page.wait_for_function("document.querySelector('img[alt=\"ProxyClaw\"]').naturalWidth === 128")
    page.get_by_text('网络活动', exact=True).wait_for()
    page.get_by_text('已代理', exact=True).wait_for()
    page.screenshot(path=str(output / 'network.png'))
    page.locator('nav').get_by_role('button', name=re.compile('^规则')).click()
    page.get_by_text('添加规则', exact=True).click()
    page.get_by_text('自动规则编辑器', exact=True).wait_for()
    page.get_by_role('button', name='浏览', exact=True).click()
    expect(page.get_by_placeholder('选择程序后自动填写')).to_have_value('C:\\应用程序\\', timeout=15000)
    page.screenshot(path=str(output / 'rule-editor.png'))
    page.get_by_role('button', name='取消', exact=True).click()
    page.locator('nav').get_by_role('button', name='代理', exact=True).click()
    page.get_by_role('button', name='新建代理组', exact=True).click()
    page.get_by_text('设置 SOCKS5 代理服务器。', exact=True).wait_for()
    page.get_by_role('button', name='取消', exact=True).click()
    page.locator('nav').get_by_role('button', name='设置', exact=True).click()
    switch = page.get_by_role('switch', name='关闭窗口后保持后台运行', exact=True)
    switch.wait_for()
    assert not any('monacoRuntime-' in url for url in resources), 'Settings eagerly loaded Monaco'
    assert switch.get_attribute('aria-checked') == 'true'
    switch.click()
    page.wait_for_function("document.querySelector('[aria-label=\"关闭窗口后保持后台运行\"]').getAttribute('aria-checked') === 'false'")
    assert page.request.get(BASE + '/api/config').json()['ui']['close_to_tray'] is False
    switch.click()
    page.wait_for_function("document.querySelector('[aria-label=\"关闭窗口后保持后台运行\"]').getAttribute('aria-checked') === 'true'")
    page.screenshot(path=str(output / 'settings.png'))
    page.get_by_role('button', name='编辑', exact=True).click()
    page.locator('.monaco-editor').wait_for()
    page.locator('.monaco-editor').click(button='right')
    page.get_by_text('命令面板', exact=False).wait_for()
    page.screenshot(path=str(output / 'config-editor.png'))
    page.keyboard.press('Escape')
    runtime_url = next(url for url in resources if 'monacoRuntime-' in url and url.endswith('.js'))
    model_count = "async url => Object.values(await import(url)).flatMap(value => [value, value?.monaco]).find(value => value?.editor?.getModels).editor.getModels().length"
    assert page.evaluate(model_count, runtime_url) == 1
    page.get_by_role('button', name='关闭', exact=True).last.click()
    assert page.evaluate(model_count, runtime_url) == 0
    page.get_by_role('button', name='编辑', exact=True).click()
    page.locator('.monaco-editor').wait_for()
    assert page.evaluate(model_count, runtime_url) == 1
    page.get_by_role('button', name='关闭', exact=True).last.click()
    assert page.evaluate(model_count, runtime_url) == 0
    assert not errors, errors
    print('PASS Chinese UI/settings, lazy Monaco loading, Chinese editor menus, repeated open/close releases models; no page errors')
    browser.close()
