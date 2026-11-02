"""Session token shared by test harnesses and the proxyclaw.exe they launch.

The management API rejects /api/ requests without the per-launch session
token (see src/transport/api_auth.hpp). Importing this module:

* picks PROXYCLAW_API_TOKEN from the environment, or generates one and
  exports it so a proxyclaw.exe started by this harness uses the same value;
* makes every ``requests`` call to the local API send the X-ProxyClaw-Token
  header, so existing ``requests.get(...)`` call sites keep working.

When attaching to an already-running proxyclaw.exe (``--no-launch``), start it
with the same PROXYCLAW_API_TOKEN (at least 32 characters).
"""
from __future__ import annotations

import os
import secrets

API_ORIGINS = ("http://127.0.0.1:18080", "http://localhost:18080")
HEADER = "X-ProxyClaw-Token"

TOKEN = os.environ.get("PROXYCLAW_API_TOKEN", "")
if len(TOKEN) < 32:
    TOKEN = secrets.token_hex(32)
    os.environ["PROXYCLAW_API_TOKEN"] = TOKEN

HEADERS = {HEADER: TOKEN}


def _install_requests_hook() -> None:
    try:
        import requests.sessions
    except ImportError:
        return
    session_cls = requests.sessions.Session
    if getattr(session_cls, "_proxyclaw_token_hook", False):
        return
    original = session_cls.request

    def request(self, method, url, *args, **kwargs):
        if isinstance(url, str) and url.startswith(API_ORIGINS):
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault(HEADER, TOKEN)
            kwargs["headers"] = headers
        return original(self, method, url, *args, **kwargs)

    session_cls.request = request
    session_cls._proxyclaw_token_hook = True


_install_requests_hook()
