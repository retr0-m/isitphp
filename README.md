# isitphp

A small CLI that crawls a website (within its own domain and subdomains),
follows the links it finds, probes a few well-known PHP entry points, and
reports whether the site is built on **PHP** — with the evidence it used.

It's passive technology fingerprinting, the same idea as Wappalyzer / WhatWeb:
only ordinary `GET`/`HEAD` requests, nothing is exploited. Use it on sites you
own or are authorised to assess (e.g. your own clients).

## Install

```bash
pip install -r requirements.txt
```

`requests` is required; `beautifulsoup4` is optional (a regex fallback is used
if it's missing, but parsing is more precise with it).

## Usage

```bash
python3 isitphp.py example.com
python3 isitphp.py https://ticinocoaching.ch --full
python3 isitphp.py x.domain.com --full --json report.json
```

Make it executable if you like:

```bash
chmod +x isitphp.py
./isitphp.py example.com
```

### Full-site scan

By default the crawl stops at `--depth 2` / `--max-pages 100`. Pass **`--full`**
for an exhaustive scan: the depth and page caps are lifted and the crawler keeps
going until **every in-scope address has been visited** — no new links left to
follow — before it closes. The report then lists **every address discovered**
and **every PHP page found**.

```bash
python3 isitphp.py ticinocoaching.ch --full
python3 isitphp.py ticinocoaching.ch --full --json ticino.json
```

Notes for `--full`:
- It can take a while and make many requests on a large site. Add `--delay 0.3`
  to be gentle on a client's server.
- Press `Ctrl-C` any time — it stops and reports what it found so far.
- A site with a crawler trap (infinite calendars, faceted filters) can expand
  the address list a lot; cap it instead with `--max-pages N` if needed.

### Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--full` | off | Exhaustive crawl: no depth/page cap; visit every in-scope address, then list them all |
| `--depth N` | 2 | How many link hops to follow from the start page (ignored with `--full`) |
| `--max-pages N` | 100 | Hard cap on pages crawled (ignored with `--full`) |
| `--list-addresses` | off | Print every discovered address (implied by `--full`) |
| `--workers N` | 6 | Concurrent requests |
| `--delay S` | 0 | Politeness pause before each request (per worker) |
| `--timeout S` | 10 | Per-request timeout |
| `--no-subdomains` | off | Stay on the exact host family; don't follow subdomains |
| `--no-probe` | off | Don't probe known PHP entry points (`index.php`, `wp-login.php`, …) |
| `--insecure` | off | Skip TLS certificate verification |
| `--json FILE` | — | Write the full machine-readable report (includes `addresses` + `php_pages`) |
| `-v`, `--verbose` | off | Print each page as it's crawled |
| `--no-color` | off | Plain output |

### Scope / subdomains

Give a bare domain (`domain.com`) and it crawls `domain.com` **and** any
subdomain (`www.`, `shop.`, `blog.` …). Give a subdomain directly
(`x.domain.com`) and the scope is `x.domain.com` and anything under it. Use
`--no-subdomains` to pin to the exact host.

## What it looks for

- **URLs** — `.php` / `.phtml` page extensions; classic query parameters
  (`?p=`, `?page_id=`, `?cat=`, `?author=`, `?page=`, `?view=`, `?action=`,
  `?mod=`, `?cmd=`, `?route=`, `?t=`, `?f=`, `?id=`, `PHPSESSID`, …).
- **HTTP headers / cookies** — `X-Powered-By: PHP`, `Server: …PHP…`,
  `PHPSESSID` and WordPress session cookies.
- **HTML** — `meta generator` (WordPress / Joomla / Drupal), `wp-content/`,
  `wp-includes/`, `wp-json`, forms that post to `*.php`, and hidden fields like
  `MAX_FILE_SIZE`, `_token`, `csrf_token`.
- **Probes** — a short, standard set of entry points
  (`/index.php`, `/wp-login.php`, `/xmlrpc.php`, `/wp-json/`, `/wp-admin/`,
  `/administrator/`) checked once per host.

Findings are grouped by confidence (**confirmed → strong → moderate → weak**)
and the verdict is the strongest tier seen.

## Exit codes

- `0` — PHP found (confirmed / strong / moderate evidence)
- `1` — no PHP evidence (or site unreachable)
- `2` — bad arguments / missing dependency
