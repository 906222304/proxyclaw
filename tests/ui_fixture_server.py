"""Isolated UI preview: API writes are kept only in memory, never sent to Clew."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit
import json
import sys

root = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'
config = {'ui': {'close_to_tray': True}, 'dns': {'enabled': False, 'mode': 'forwarder', 'upstream_host': '1.1.1.1'}, 'log_level': 'info'}
group = {'id': 0, 'name': '默认代理', 'host': '127.0.0.1', 'port': 7890, 'type': 'socks5', 'test_url': 'https://www.google.com'}
rules = [{'id': 'sample', 'name': 'Codex 桌面客户端', 'enabled': True, 'process_name': 'ChatGPT.exe', 'cmdline_pattern': '', 'hack_tree': True, 'protocol': 'both', 'dst_filter': {'include_cidrs': [], 'exclude_cidrs': [], 'include_ports': [], 'exclude_ports': []}, 'proxy_group_id': 0, 'proxy': {'type': 'socks5', 'host': '127.0.0.1', 'port': 7890}}]
startup = {'enabled': False, 'start_minimized': False}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(root), **kwargs)
    def log_message(self, *args): pass
    def reply(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = urlsplit(self.path).path
        if not path.startswith('/api/'): return super().do_GET()
        if path == '/api/config': return self.reply(config)
        if path == '/api/autostart': return self.reply(startup)
        if path == '/api/auto-rules': return self.reply(rules)
        if path == '/api/proxy-groups': return self.reply([group])
        if path == '/api/stats': return self.reply({'hijacked_pids': 1, 'auto_rules_count': len(rules)})
        if path == '/api/tcp': return self.reply([{'pid': 4321, 'local_ip': '127.0.0.1', 'local_port': 51234, 'remote_ip': '104.18.32.7', 'remote_port': 443, 'state': 'ESTABLISHED', 'proxy_status': 'PROXIED', 'pid_alive': True, 'process_name': 'ChatGPT.exe', 'hijacked': True, 'dest': '104.18.32.7:443'}])
        return self.reply([])
    def do_PUT(self):
        global config
        data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        path = urlsplit(self.path).path
        if path == '/api/config': config = data
        elif path == '/api/autostart': startup.update(data)
        self.reply(data)
    def do_POST(self):
        if self.path == '/api/shell/browse-exe':
            return self.reply({'path': 'C:\\应用程序\\中文示例.exe', 'dir': 'C:\\应用程序\\', 'name': '中文示例.exe'})
        return self.reply({'latency_ms': 80})

port = int(sys.argv[1]) if len(sys.argv) > 1 else 23641
print(f'Isolated Chinese UI preview at http://127.0.0.1:{port}', flush=True)
ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
