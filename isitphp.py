#!/usr/bin/env python3
"""
isitphp — detect whether a website is built on PHP.

Crawls a site within its own domain (and subdomains), follows the links it
finds, probes a handful of well-known PHP entry points, and reports the
evidence it collected from URLs, HTTP headers, cookies and HTML.

This is passive technology fingerprinting — the same thing a browser or a tool
like Wappalyzer/WhatWeb does. It only issues ordinary GET/HEAD requests and
never tries to exploit anything. Point it at sites you own or are authorised
to assess (your own clients).

Usage:
    python3 isitphp.py example.com
    python3 isitphp.py https://ticinocoaching.ch --depth 3 --max-pages 200
    python3 isitphp.py x.domain.com --json report.json

Dependencies:
    requests          (required)
    beautifulsoup4    (optional — a regex fallback is used if missing)
"""

import argparse
import re
import sys
import time
import json
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    sys.stderr.write(
        "error: the 'requests' library is required.\n"
        "       install it with:  pip install requests\n"
    )
    sys.exit(2)

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False


# --------------------------------------------------------------------------- #
#  Appearance
# --------------------------------------------------------------------------- #

class C:
    """ANSI colour codes, auto-disabled when output is not a terminal."""
    enabled = sys.stdout.isatty()

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def paint(cls, text, *styles):
        if not cls.enabled:
            return text
        return "".join(styles) + text + cls.RESET


BANNER = r"""
   _      _ _   ___  _  _ ___
  (_)____(_) |_| _ \| || | _ \
  | (_-<| |  _|  _/| __ |  _/
  |_/__/|_|\__|_|  |_||_|_|       is it PHP?
"""


def print_banner():
    print(C.paint(BANNER, C.CYAN, C.BOLD))
    print(C.paint("  website PHP fingerprinter", C.GREY) +
          C.paint("  ·  crawl · probe · report\n", C.DIM))


# --------------------------------------------------------------------------- #
#  Evidence model
# --------------------------------------------------------------------------- #

# Confidence tiers, strongest first.
CONFIRMED = "confirmed"   # effectively proves PHP
STRONG = "strong"         # very likely PHP (e.g. WordPress)
MODERATE = "moderate"     # PHP-style, but other stacks can mimic
WEAK = "weak"             # ambiguous hint

TIER_ORDER = [CONFIRMED, STRONG, MODERATE, WEAK]
TIER_COLOR = {
    CONFIRMED: C.GREEN,
    STRONG: C.GREEN,
    MODERATE: C.YELLOW,
    WEAK: C.GREY,
}


class Evidence:
    __slots__ = ("tier", "signal", "detail", "where")

    def __init__(self, tier, signal, detail, where):
        self.tier = tier
        self.signal = signal      # short category label
        self.detail = detail      # what exactly was seen
        self.where = where        # URL it was seen on

    def key(self):
        # Dedupe on the meaning of the finding, not the page it came from.
        return (self.tier, self.signal, self.detail)


# PHP file extensions (as a page's own extension).
PHP_EXTENSIONS = (".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar")

# Query parameters, grouped by how strongly they point at PHP.
# These come from classic WordPress / PHP routing / forum / e-commerce patterns.
PARAMS_CONFIRMED = {
    "phpsessid",            # PHP session id leaked into the URL
}
PARAMS_STRONG = {
    "page_id", "cat", "author",     # WordPress query vars
    "route",                        # OpenCart
}
PARAMS_MODERATE = {
    "p", "preview",                 # WordPress
    "page", "view", "mod", "module", "cmd",  # index.php?page=... routing
    "t", "f",                       # phpBB topic/forum ids
}
PARAMS_WEAK = {
    "action", "id", "item",         # generic, used everywhere
}

PARAM_TIER = {}
for _name in PARAMS_CONFIRMED:
    PARAM_TIER[_name] = CONFIRMED
for _name in PARAMS_STRONG:
    PARAM_TIER[_name] = STRONG
for _name in PARAMS_MODERATE:
    PARAM_TIER[_name] = MODERATE
for _name in PARAMS_WEAK:
    PARAM_TIER[_name] = WEAK

# Well-known PHP / WordPress / CMS entry points to probe per in-scope host.
# All are standard, non-destructive GET targets used purely to fingerprint.
PROBE_PATHS = [
    "/index.php",
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-json/",
    "/wp-admin/",
    "/administrator/",       # Joomla
]

# Hidden form field names that are characteristic of PHP apps/frameworks.
HIDDEN_FIELD_TIER = {
    "max_file_size": MODERATE,   # built-in PHP upload directive
    "_token": WEAK,              # Laravel CSRF (also mimicked elsewhere)
    "csrf_token": WEAK,
}

# HTML link-extraction fallback when BeautifulSoup is unavailable.
HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#>\s]+)""", re.I)
META_GEN_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)""",
    re.I,
)
HIDDEN_INPUT_RE = re.compile(
    r"""<input[^>]+type\s*=\s*["']hidden["'][^>]*>""", re.I)
INPUT_NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)""", re.I)


# --------------------------------------------------------------------------- #
#  Detection
# --------------------------------------------------------------------------- #

def detect_from_url(url):
    """Signals readable from a URL string alone (extension, query params).

    The evidence is recorded against ``url`` itself — whether that URL is a
    page we fetched or a link we merely saw in some page's HTML.
    """
    found = []
    parsed = urlparse(url)
    path = parsed.path.lower()

    # URL extension — look at the last path component.
    last = path.rstrip("/").rsplit("/", 1)[-1]
    for ext in PHP_EXTENSIONS:
        if last.endswith(ext):
            found.append(Evidence(
                CONFIRMED, "url-extension",
                "URL ends in {}".format(ext), url))
            break

    # Query parameters.
    if parsed.query:
        for name in parse_qs(parsed.query, keep_blank_values=True):
            tier = PARAM_TIER.get(name.lower())
            if tier:
                found.append(Evidence(
                    tier, "query-param",
                    "?{}= — classic PHP query parameter".format(name), url))
    return found


def detect_from_headers(headers, cookies, final_url):
    """Signals from HTTP response headers and cookies."""
    found = []

    powered = headers.get("X-Powered-By", "")
    if "php" in powered.lower():
        found.append(Evidence(
            CONFIRMED, "header",
            "X-Powered-By: {}".format(powered.strip()), final_url))

    server = headers.get("Server", "")
    if "php" in server.lower():
        found.append(Evidence(
            STRONG, "header",
            "Server: {}".format(server.strip()), final_url))

    # Cookies — PHPSESSID is a dead giveaway; WP cookies imply PHP too.
    cookie_names = set()
    try:
        cookie_names.update(c.name for c in cookies)
    except TypeError:
        pass
    raw_setcookie = headers.get("Set-Cookie", "")
    for m in re.finditer(r"(?:^|,\s*)([^=;,\s]+)=", raw_setcookie):
        cookie_names.add(m.group(1))

    for name in cookie_names:
        low = name.lower()
        if low == "phpsessid":
            found.append(Evidence(
                CONFIRMED, "cookie",
                "PHPSESSID session cookie set", final_url))
        elif low.startswith(("wordpress_", "wp-settings", "wp_")):
            found.append(Evidence(
                STRONG, "cookie",
                "WordPress cookie '{}' (WordPress is PHP)".format(name),
                final_url))

    return found


def detect_from_html(html, final_url):
    """Signals from the HTML body: generator, WP paths, forms, hidden fields."""
    found = []
    low = html.lower()

    # Generator meta tag.
    m = META_GEN_RE.search(html)
    if m:
        gen = m.group(1)
        g = gen.lower()
        if "wordpress" in g:
            found.append(Evidence(
                STRONG, "generator",
                "meta generator: {} (WordPress is PHP)".format(gen), final_url))
        elif "joomla" in g or "drupal" in g:
            found.append(Evidence(
                STRONG, "generator",
                "meta generator: {} (PHP CMS)".format(gen), final_url))

    # WordPress fingerprints in markup.
    for needle, label in (("wp-content", "wp-content/ asset path"),
                          ("wp-includes", "wp-includes/ asset path"),
                          ("/wp-json", "wp-json REST route")):
        if needle in low:
            found.append(Evidence(
                STRONG, "wordpress",
                "{} present in HTML".format(label), final_url))

    # Hidden form fields.
    if HAVE_BS4:
        soup = BeautifulSoup(html, "html.parser")
        hidden_inputs = [i for i in soup.find_all("input")
                         if (i.get("type") or "").lower() == "hidden"]
        names = [i.get("name", "") for i in hidden_inputs]
        form_actions = [f.get("action", "") for f in soup.find_all("form")]
    else:
        names = []
        for tag in HIDDEN_INPUT_RE.findall(html):
            nm = INPUT_NAME_RE.search(tag)
            if nm:
                names.append(nm.group(1))
        form_actions = re.findall(
            r"""<form[^>]+action\s*=\s*["']([^"']+)""", html, re.I)

    for nm in names:
        tier = HIDDEN_FIELD_TIER.get((nm or "").lower())
        if tier:
            found.append(Evidence(
                tier, "form-field",
                "hidden field name=\"{}\"".format(nm), final_url))

    # Forms that post to a .php script.
    for action in form_actions:
        a = (action or "").lower().split("?", 1)[0]
        if any(a.endswith(ext) for ext in PHP_EXTENSIONS):
            found.append(Evidence(
                STRONG, "form-action",
                "form submits to {}".format(action), final_url))
            break

    return found


# --------------------------------------------------------------------------- #
#  Link extraction
# --------------------------------------------------------------------------- #

def extract_links(html, base_url):
    """Return absolute, de-fragmented links found in the page."""
    links = set()
    if HAVE_BS4:
        soup = BeautifulSoup(html, "html.parser")
        raw = []
        for tag, attr in (("a", "href"), ("link", "href"),
                          ("script", "src"), ("form", "action")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if val:
                    raw.append(val)
    else:
        raw = HREF_RE.findall(html)

    for href in raw:
        href = href.strip()
        if not href or href.lower().startswith(
                ("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        absolute = urljoin(base_url, href)
        absolute, _ = urldefrag(absolute)
        if absolute.startswith(("http://", "https://")):
            links.add(absolute)
    return links


# --------------------------------------------------------------------------- #
#  Scope
# --------------------------------------------------------------------------- #

def base_domain(host):
    """Normalise a host into the base domain we constrain the crawl to."""
    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def in_scope(url, base, include_subdomains):
    host = urlparse(url).hostname or ""
    host = host.lower()
    if host == base:
        return True
    if include_subdomains and host.endswith("." + base):
        return True
    return False


# --------------------------------------------------------------------------- #
#  Crawler
# --------------------------------------------------------------------------- #

class Crawler:
    def __init__(self, start_url, base, args):
        self.base = base
        self.args = args
        self.start_url = start_url

        self.visited = set()
        self.evidence = {}          # key() -> Evidence (deduped)
        self.pages_ok = 0
        self.pages_err = 0
        self.probed_hosts = set()
        self.lock = Lock()

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": args.user_agent})
        adapter = HTTPAdapter(pool_connections=args.workers,
                              pool_maxsize=args.workers)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    # -- helpers -----------------------------------------------------------
    def add_evidence(self, ev_list):
        with self.lock:
            for ev in ev_list:
                self.evidence.setdefault(ev.key(), ev)

    def log(self, msg):
        if self.args.verbose:
            with self.lock:
                print(C.paint("  [·] ", C.GREY) + msg)

    def fetch(self, url, method="GET"):
        try:
            resp = self.session.request(
                method, url, timeout=self.args.timeout,
                allow_redirects=True, verify=not self.args.insecure)
            return resp
        except requests.RequestException as exc:
            self.log(C.paint("request failed: {} ({})".format(url, exc),
                             C.RED))
            return None

    # -- probing -----------------------------------------------------------
    def probe_host(self, host_root):
        """GET a few known PHP entry points on a host to confirm PHP."""
        if self.args.no_probe:
            return
        with self.lock:
            if host_root in self.probed_hosts:
                return
            self.probed_hosts.add(host_root)

        for path in PROBE_PATHS:
            url = host_root.rstrip("/") + path
            if self.args.delay:
                time.sleep(self.args.delay)
            resp = self.fetch(url)
            if resp is None:
                continue
            # A redirect to a login or a 200/403 on these paths, together with
            # PHP headers/cookies, is what confirms the stack.
            if resp.status_code < 400 or resp.status_code in (401, 403):
                self.log("probe {} -> {}".format(url, resp.status_code))
                self.add_evidence(detect_from_url(resp.url))
                self.add_evidence(detect_from_headers(
                    resp.headers, resp.cookies, resp.url))
                # Only parse HTML bodies, and only when not too large.
                ctype = resp.headers.get("Content-Type", "")
                if "html" in ctype.lower():
                    self.add_evidence(detect_from_html(resp.text, resp.url))

    # -- single page -------------------------------------------------------
    def process(self, url, depth):
        if self.args.delay:
            time.sleep(self.args.delay)
        resp = self.fetch(url)
        if resp is None:
            with self.lock:
                self.pages_err += 1
            return []

        with self.lock:
            self.pages_ok += 1
        final = resp.url

        # URL + header evidence always apply.
        self.add_evidence(detect_from_url(final))
        self.add_evidence(detect_from_headers(
            resp.headers, resp.cookies, final))

        ctype = resp.headers.get("Content-Type", "")
        new_links = []
        if "html" in ctype.lower():
            html = resp.text
            self.add_evidence(detect_from_html(html, final))
            for link in extract_links(html, final):
                # Capture URL-level signals even for links we won't crawl.
                self.add_evidence(detect_from_url(link))
                if in_scope(link, self.base, self.args.include_subdomains):
                    new_links.append(link)

        self.log("[{}] depth {} {} ({} links)".format(
            resp.status_code, depth, final, len(new_links)))
        return new_links

    # -- main loop ---------------------------------------------------------
    def run(self):
        queue = deque([(self.start_url, 0)])
        self.visited.add(self.start_url)

        # Probe the starting host up front.
        p = urlparse(self.start_url)
        self.probe_host("{}://{}".format(p.scheme, p.netloc))

        with ThreadPoolExecutor(max_workers=self.args.workers) as pool:
            while queue and len(self.visited) <= self.args.max_pages:
                batch = []
                while queue and len(batch) < self.args.workers:
                    batch.append(queue.popleft())

                futures = {pool.submit(self.process, url, d): (url, d)
                           for url, d in batch}
                for fut in as_completed(futures):
                    url, d = futures[fut]
                    try:
                        new_links = fut.result()
                    except Exception as exc:          # noqa: BLE001
                        self.log(C.paint("worker error: {}".format(exc), C.RED))
                        continue
                    if d >= self.args.depth:
                        continue
                    for link in new_links:
                        with self.lock:
                            if link in self.visited:
                                continue
                            if len(self.visited) > self.args.max_pages:
                                break
                            self.visited.add(link)
                        queue.append((link, d + 1))
                        # Probe any newly seen host too.
                        lp = urlparse(link)
                        self.probe_host("{}://{}".format(lp.scheme, lp.netloc))


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

def verdict(evidence):
    tiers = {ev.tier for ev in evidence}
    if CONFIRMED in tiers:
        return ("YES — PHP confirmed", C.GREEN)
    if STRONG in tiers:
        return ("LIKELY PHP", C.GREEN)
    if MODERATE in tiers:
        return ("POSSIBLY PHP", C.YELLOW)
    if WEAK in tiers:
        return ("INCONCLUSIVE — only weak hints", C.YELLOW)
    return ("NO PHP indicators found", C.RED)


def print_report(crawler, target, elapsed):
    evidence = list(crawler.evidence.values())
    label, color = verdict(evidence)

    print()
    print(C.paint("─" * 60, C.GREY))
    print(C.paint(" RESULT  ", C.BOLD) + C.paint(label, color, C.BOLD))
    print(C.paint("─" * 60, C.GREY))
    print("  target        : {}".format(target))
    print("  pages crawled : {}".format(crawler.pages_ok))
    print("  failed        : {}".format(crawler.pages_err))
    print("  hosts probed  : {}".format(len(crawler.probed_hosts)))
    print("  time          : {:.1f}s".format(elapsed))
    print()

    if not evidence:
        print(C.paint("  No PHP signals were observed on the crawled pages.",
                     C.GREY))
        print(C.paint("  (That is not proof of absence — the site may hide it "
                     "behind a proxy/CDN or pretty URLs.)", C.DIM))
        return

    # Group findings by confidence tier.
    by_tier = {t: [] for t in TIER_ORDER}
    for ev in evidence:
        by_tier[ev.tier].append(ev)

    for tier in TIER_ORDER:
        items = by_tier[tier]
        if not items:
            continue
        head = "  {} evidence ({})".format(tier.upper(), len(items))
        print(C.paint(head, TIER_COLOR[tier], C.BOLD))
        for ev in sorted(items, key=lambda e: e.signal):
            print("    {} {}".format(
                C.paint("•", TIER_COLOR[tier]),
                ev.detail))
            print(C.paint("        seen on: {}".format(ev.where), C.GREY))
        print()


def build_json(crawler, target, label, elapsed):
    return {
        "target": target,
        "verdict": label,
        "pages_crawled": crawler.pages_ok,
        "pages_failed": crawler.pages_err,
        "hosts_probed": sorted(crawler.probed_hosts),
        "elapsed_seconds": round(elapsed, 2),
        "evidence": [
            {"tier": ev.tier, "signal": ev.signal,
             "detail": ev.detail, "url": ev.where}
            for ev in crawler.evidence.values()
        ],
    }


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def normalise_target(raw):
    """Accept bare domains or full URLs; return (start_url, base_domain)."""
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("could not parse a hostname from '{}'".format(raw))
    base = base_domain(parsed.hostname)
    return raw, base


def resolve_start(session, start_url, timeout, insecure):
    """Ensure the start URL is reachable; fall back https->http once."""
    try:
        r = session.get(start_url, timeout=timeout, allow_redirects=True,
                        verify=not insecure)
        return r.url
    except requests.RequestException:
        if start_url.startswith("https://"):
            alt = "http://" + start_url[len("https://"):]
            try:
                r = session.get(alt, timeout=timeout, allow_redirects=True,
                                verify=not insecure)
                return r.url
            except requests.RequestException:
                pass
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="isitphp",
        description="Crawl a website and report whether it is built on PHP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  isitphp example.com\n"
               "  isitphp https://ticinocoaching.ch --depth 3 --max-pages 200\n"
               "  isitphp x.domain.com --json out.json\n",
    )
    parser.add_argument("target", help="website URL or domain to scan")
    parser.add_argument("--depth", type=int, default=2,
                        help="max link depth to follow (default: 2)")
    parser.add_argument("--max-pages", type=int, default=100,
                        help="max pages to crawl (default: 100)")
    parser.add_argument("--workers", type=int, default=6,
                        help="concurrent requests (default: 6)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconds to wait before each request per worker "
                             "(default: 0)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-request timeout in seconds (default: 10)")
    parser.add_argument("--no-subdomains", dest="include_subdomains",
                        action="store_false",
                        help="do not follow subdomains of the base domain "
                             "(subdomains are included by default)")
    parser.add_argument("--no-probe", action="store_true",
                        help="do not probe well-known PHP entry points")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification")
    parser.add_argument("--user-agent",
                        default="isitphp/1.0 (+tech-detection)",
                        help="User-Agent header to send")
    parser.add_argument("--json", metavar="FILE",
                        help="write the full report as JSON to FILE")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print each page as it is crawled")
    parser.add_argument("--no-color", action="store_true",
                        help="disable coloured output")
    args = parser.parse_args(argv)

    if args.no_color:
        C.enabled = False

    print_banner()
    if not HAVE_BS4:
        print(C.paint("  note: beautifulsoup4 not installed — using the regex "
                     "fallback (less precise). Install with: pip install "
                     "beautifulsoup4\n", C.YELLOW))

    try:
        start_url, base = normalise_target(args.target)
    except ValueError as exc:
        print(C.paint("error: {}".format(exc), C.RED))
        return 2

    print("  target : {}".format(C.paint(start_url, C.BOLD)))
    print("  scope  : {}{}".format(
        C.paint(base, C.BOLD),
        " + subdomains" if args.include_subdomains else " (exact host family)"))
    print("  limits : depth {} · {} pages · {} workers\n".format(
        args.depth, args.max_pages, args.workers))

    # Confirm the site answers, and follow any entry redirect.
    probe_session = requests.Session()
    probe_session.headers.update({"User-Agent": args.user_agent})
    final_start = resolve_start(probe_session, start_url,
                                args.timeout, args.insecure)
    if final_start is None:
        print(C.paint("error: could not reach {} (and http:// fallback "
                     "failed).".format(start_url), C.RED))
        return 1
    start_url = final_start
    base = base_domain(urlparse(start_url).hostname)

    crawler = Crawler(start_url, base, args)
    t0 = time.time()
    try:
        crawler.run()
    except KeyboardInterrupt:
        print(C.paint("\n  interrupted — reporting what was found so far…",
                     C.YELLOW))
    elapsed = time.time() - t0

    print_report(crawler, args.target, elapsed)

    if args.json:
        label, _ = verdict(list(crawler.evidence.values()))
        data = build_json(crawler, args.target, label, elapsed)
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            print(C.paint("  report written to {}".format(args.json), C.CYAN))
        except OSError as exc:
            print(C.paint("  could not write JSON: {}".format(exc), C.RED))

    # Exit code: 0 if PHP found (confirmed/strong/moderate), 1 otherwise.
    tiers = {ev.tier for ev in crawler.evidence.values()}
    return 0 if tiers & {CONFIRMED, STRONG, MODERATE} else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
