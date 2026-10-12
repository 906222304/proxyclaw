import pathlib
import subprocess
import sys
import time
import urllib.request
import socket
import os
ROOT = pathlib.Path(__file__).resolve().parents[1]
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
base = f'http://127.0.0.1:{port}'
env = os.environ.copy()
env['PROXYCLAW_UI_TEST_URL'] = base
server = subprocess.Popen([sys.executable, str(ROOT/'tests/ui_fixture_server.py'), str(port)], cwd=ROOT)
try:
    for _ in range(60):
        try:
            with urllib.request.urlopen(base, timeout=.3): pass
            break
        except Exception:
            if server.poll() is not None: raise RuntimeError('isolated preview failed to start')
            time.sleep(.1)
    else: raise RuntimeError('isolated preview timed out')
    scripts = ['log_viewer_smoke.py'] if '--logs' in sys.argv else ['ui_optimization_smoke.py']
    for script in scripts:
        subprocess.run([sys.executable, str(ROOT/'tests'/script)], cwd=ROOT, env=env, check=True, timeout=90)
finally:
    server.terminate()
    server.wait(timeout=10)
