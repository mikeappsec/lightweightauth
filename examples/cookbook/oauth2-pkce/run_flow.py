#!/usr/bin/env python3
"""End-to-end OAuth2 Authorization Code + PKCE driver.

Runs against the lwauth-idp + lwauth gateway deployed in a kind cluster
by the OAuth2-PKCE cookbook recipe. Uses only Python 3 stdlib so a
fresh checkout works without `pip install`.

What it does:
    1.  port-forwards lwauth-idp:9090 -> 127.0.0.1:9090
    2.  port-forwards lwauth-gateway:80 -> 127.0.0.1:8080
    3.  generates a fresh PKCE verifier + S256 challenge
    4.  POSTs creds to /oauth2/authorize, captures the 302 `code`
    5.  exchanges the code at /oauth2/token, receives a JWT
    6.  GET /get on the gateway with `Authorization: Bearer <jwt>` -> 200
    7.  GET /get with no bearer -> 401, with a tampered bearer -> 401

Exit 0 on full success, exit 1 on the first failure. All probes print
a one-line status so the output is grep-friendly for CI.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from typing import Optional


# ----- small helpers --------------------------------------------------

def b64url(b: bytes) -> str:
    """Base64url-no-pad, the encoding RFC 7636 PKCE expects."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pkce_pair() -> tuple[str, str]:
    """Return (verifier, S256 challenge). Verifier is 43 chars, RFC-legal."""
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Block until `host:port` accepts a TCP connection or timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


class HTTPClient:
    """Thin wrapper around urllib that:
       - never follows redirects (we need the 302 Location header)
       - returns (status, headers, body) so callers can branch on each
       - captures both 2xx and 4xx without raising (avoids HTTPError)."""

    def request(
        self,
        method: str,
        url: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        # Custom opener: no auto-redirect, no proxy lookup. The default
        # opener silently follows 302s, which would consume our auth code.
        opener = urllib.request.build_opener(
            _NoRedirectHandler(), urllib.request.ProxyHandler({})
        )
        try:
            resp = opener.open(req, timeout=10)
            return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib's default handler turns 3xx into a follow; we want the raw
    response so we can read the Location header."""

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


# ----- port-forward management ---------------------------------------

class PortForward:
    """Wraps `kubectl port-forward` as a context manager.

    Stops the child on exit so the script can fail loudly mid-flow
    without leaking forwards. Using `kubectl` directly (rather than the
    `kubernetes` Python client) keeps this driver dep-free."""

    def __init__(self, namespace: str, target: str, local_port: int, remote_port: int):
        self.namespace = namespace
        self.target = target
        self.local_port = local_port
        self.remote_port = remote_port
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "PortForward":
        kubectl = shutil.which("kubectl") or "kubectl"
        self._proc = subprocess.Popen(
            [
                kubectl, "port-forward",
                "-n", self.namespace,
                self.target,
                f"{self.local_port}:{self.remote_port}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_for_port("127.0.0.1", self.local_port, timeout=15):
            self.__exit__(None, None, None)
            raise RuntimeError(
                f"port-forward to {self.target}:{self.remote_port} did not come up"
            )
        return self

    def __exit__(self, *_):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()


# ----- the actual flow ----------------------------------------------

IDP_URL = "http://127.0.0.1:9090"
GW_URL = "http://127.0.0.1:8080"
CLIENT_ID = "demo-client"
REDIRECT_URI = "http://localhost:8765/callback"


def main() -> int:
    http = HTTPClient()
    failures: list[str] = []

    with PortForward("demo", "svc/lwauth-idp", 9090, 9090), \
         PortForward("demo", "svc/lwauth-gateway", 8080, 80):

        # 3) PKCE pair
        verifier, challenge = pkce_pair()
        print(f"-- PKCE: verifier={verifier[:12]}.. challenge={challenge[:12]}..")

        # 4) authorize: POST creds, capture 302 -> code
        state = secrets.token_urlsafe(16)
        form = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid email",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": "alice",
            "password": "wonderland",
        }).encode()
        status, headers, _ = http.request(
            "POST", f"{IDP_URL}/oauth2/authorize",
            body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if status != 302:
            print(f"!! authorize returned {status}, want 302")
            return 1
        loc = headers.get("Location") or headers.get("location") or ""
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        code = (qs.get("code") or [""])[0]
        if not code:
            print(f"!! no code in Location: {loc!r}")
            return 1
        # Verify state round-trips (CSRF protection).
        returned_state = (qs.get("state") or [""])[0]
        if returned_state != state:
            print(f"!! state mismatch: sent {state!r}, got {returned_state!r}")
            return 1
        print(f"-- authorize: 302 -> code={code[:12]}.. state={returned_state[:8]}..")

        # 5) token exchange
        tok_form = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }).encode()
        status, _, body = http.request(
            "POST", f"{IDP_URL}/oauth2/token",
            body=tok_form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if status != 200:
            print(f"!! token returned {status}, body={body!r}")
            return 1
        tok = json.loads(body)
        jwt = tok.get("access_token", "")
        if not jwt:
            print(f"!! no access_token in /token body: {body!r}")
            return 1
        print(
            f"-- token:     200 access_token={jwt[:18]}.. "
            f"expires_in={tok.get('expires_in')}s id_token={'yes' if tok.get('id_token') else 'no'}"
        )

        # 6) gateway with valid bearer -> 200
        status, _, _ = http.request(
            "GET", f"{GW_URL}/get",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        print(f"-- gateway:   GET /get with bearer       -> {status}")
        if status != 200:
            failures.append(f"with-bearer: got {status}, want 200")

        # 7a) gateway without bearer -> 401
        status, _, _ = http.request("GET", f"{GW_URL}/get")
        print(f"-- gateway:   GET /get without bearer    -> {status}")
        if status != 401:
            failures.append(f"no-bearer: got {status}, want 401")

        # 7b) gateway with tampered bearer -> 401
        tampered = jwt[:-4] + "AAAA"
        status, _, _ = http.request(
            "GET", f"{GW_URL}/get",
            headers={"Authorization": f"Bearer {tampered}"},
        )
        print(f"-- gateway:   GET /get with tampered JWT -> {status}")
        if status != 401:
            failures.append(f"tampered: got {status}, want 401")

    if failures:
        print("\nFAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
