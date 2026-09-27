#!/usr/bin/env python3
"""
Check a list of domains and report the Registrant Organization.

Writes the domains whose registrant Organization matches --org, one per line,
to -o (default valid_domains.txt). Results are flushed as they arrive, so a
partial run still leaves a usable file.

Usage:
    python3 whois_check.py -l apex_domains.txt -o valid_apex_domains.txt --org "Google LLC"

"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

RDAP_BOOTSTRAP = "https://rdap.org/domain/{}"
UA = "registrant-org-check/2.0"
SPLIT = "\n\n===== referral: "

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

REFERRAL_RE = re.compile(
    r"^\s*(?:Registrar\s+WHOIS\s+Server|Whois\s+Server|ReferralServer|refer)\s*:\s*(\S+)\s*$", re.I | re.M)
RATE_LIMIT_RE = re.compile(
    r"(rate\s*limit|query\s*rate|queries\s*per|too\s*many\s*(requests|connections)|"
    r"limit\s*exceeded|try\s*again\s*later|access\s*denied|quota\s*exceeded|excessive)", re.I)
CONNECT_ERR_RE = re.compile(
    r"(network\s*is\s*unreachable|connection\s*refused|connection\s*timed\s*out|no\s*route\s*to\s*host|"
    r"name\s*or\s*service\s*not\s*known|temporary\s*failure\s*in\s*name\s*resolution|host\s*unreachable|"
    r"connect:|read:\s*connection\s*reset)", re.I)
NO_SERVER_RE = re.compile(
    r"(no\s*whois\s*server\s*is\s*known|this\s*tld\s*has\s*no\s*whois\s*server|"
    r"no\s*whois\s*server\s*known)", re.I)
NOT_FOUND_RE = re.compile(
    r"(^|\n)\s*(no\s*match|not\s*found|no\s*entries\s*found|no\s*data\s*found|"
    r"domain\s*not\s*found|no\s*object\s*found|status:\s*(free|available))", re.I)
REDACTED_RE = re.compile(
    r"(redact|data\s*protected|not\s*disclosed|gdpr|withheld|statutory\s*masking|"
    r"privacy|anonymi[sz]ed|obscured)", re.I)

PLACEHOLDER_RE = re.compile(
    r"^(n/?a|none|null|-+|\.+|not\s*applicable|not\s*disclosed|not\s*available|"
    r"redacted.*|.*redacted\s*for\s*privacy.*|data\s*protected.*|gdpr.*|.*masked.*|"
    r"statutory\s*masking.*|withheld.*|privacy.*|anonymi[sz]e.*|obscured.*|"
    r"see\s*.*for\s*.*|please\s*(query|contact).*|\*+)$", re.I)

PROXY_RE = re.compile(
    r"(domains\s*by\s*proxy|whois\s*privacy|privacy\s*protect|privacyguardian|contact\s*privacy|"
    r"perfect\s*privacy|withheld\s*for\s*privacy|identity\s*protect|domain\s*protection\s*services|"
    r"proxy\s*protection|super\s*privacy\s*service|private\s*whois|redacted\s*for\s*privacy)", re.I)

OTHER_BLOCK_RE = re.compile(
    r"^\s*(admin|administrative|tech|technical|billing|registrar|reseller|zone|abuse|"
    r"name\s*server|nserver|dnssec|domain|sponsoring)\b", re.I)

GREEN, BOLD, DIM, RESET = "\033[32m", "\033[1m", "\033[2m", "\033[0m"

DEFAULT_SERVER = "__default__"
_guard = threading.Lock()
_locks, _last = {}, {}

WHOIS_DEAD_RE = re.compile(
    r"(connect failed|whois command failed|no whois server|empty response)", re.I)
REFERRAL_PROBLEM_PREFIX = "referral "

_mode_lock = threading.Lock()
_whois_failures = 0     
_forced_rdap = False
_since_switch = 0

_flag_lock = threading.Lock()
_use_H = True   


def throttle(server, interval):
    with _guard:
        lock = _locks.setdefault(server, threading.Lock())
    with lock:
        wait = interval - (time.time() - _last.get(server, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last[server] = time.time()


def hostname(value):
    return re.sub(r"^\w+://", "", (value or "").strip()).split("/")[0].split(":")[0].strip().rstrip(".").lower()


def norm(value):
    """Casefold and reduce to alphanumerics+spaces so 'Google LLC.' == 'google llc'."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", (value or "").lower())).strip()


# ---------------------------------------------------------------- whois

def run_whois(domain, server=None, timeout=30, interval=2.0):
    global _use_H
    tld = domain.rsplit(".", 1)[-1]
    throttle(server or f"{DEFAULT_SERVER}:{tld}", interval)

    def call(use_h):
        cmd = ["whois"] + (["-H"] if use_h else []) + (["-h", server] if server else []) + [domain]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p, (p.stdout or "") + (p.stderr or "")

    try:
        with _flag_lock:
            use_h = _use_H
        p, out = call(use_h)
        if use_h and p.returncode != 0 and re.search(r"(invalid|unrecognized|illegal)\s+option|^usage:", out, re.I | re.M):
            with _flag_lock:
                _use_H = False
            _, out = call(False)
        return out
    except subprocess.TimeoutExpired:
        return ""
    except OSError as e:
        return f"__ERROR__ {e}"


def ask_whois(domain, server, args):
    raw, problem = "", ""
    for attempt in range(args.retries + 1):
        raw = run_whois(domain, server=server, timeout=args.timeout, interval=args.server_interval)
        if raw.startswith("__ERROR__"):
            return raw, "whois command failed"
        if not raw.strip():
            problem = "empty response / timeout"
        elif NO_SERVER_RE.search(raw):
            return raw, "no whois server for this tld"
        elif CONNECT_ERR_RE.search(raw) and len(raw.strip()) < 400:
            problem = "connect failed (port 43 blocked?)"
            break
        elif RATE_LIMIT_RE.search(raw) and not registrant_block(raw):
            problem = "rate limited"
        else:
            return raw, ""
        if attempt < args.retries:
            time.sleep(args.backoff * (attempt + 1))
    return raw, problem


def query_whois(domain, args):
    raw, problem = ask_whois(domain, None, args)
    servers = ["registry"]
    if problem:
        return raw, problem, servers

    combined = raw
    seen = set()
    for _ in range(max(0, args.max_referrals)):
        if parse_whois_org(combined, args.allow_name)[0]:
            break
        m = REFERRAL_RE.search(combined.split(SPLIT)[-1])
        if not m:
            break
        server = hostname(m.group(1))
        if not server or server in ("none", "null") or server in seen:
            break
        seen.add(server)
        thick, thick_problem = ask_whois(domain, server, args)
        servers.append(server)
        if thick_problem:
            return combined, f"referral {server}: {thick_problem}", servers
        combined += SPLIT + server + " =====\n" + thick
    return combined, "", servers


def registrant_block(raw):
    """Text of registrant-scoped lines only, so privacy boilerplate elsewhere is ignored."""
    out, in_block = [], False
    for line in (raw or "").splitlines():
        if re.match(r"^\s*registrant\s*(contact)?\s*:?\s*$", line, re.I):
            in_block = True
            continue
        if re.match(r"^\s*registrant\b", line, re.I):
            out.append(line)
            continue
        if in_block:
            if OTHER_BLOCK_RE.match(line) or re.match(r"^\s*>>>", line):
                in_block = False
            elif line.strip():
                out.append(line)
    return "\n".join(out)


def clean_org(value):
    value = re.sub(r"\s+", " ", (value or "").strip().strip('"'))
    if not value or PLACEHOLDER_RE.match(value) or len(value) < 2:
        return None
    return value


def parse_whois_org(raw, allow_name=True):
    """Return (organization, source_field) or (None, '')."""
    if not raw:
        return None, ""
    for section in reversed(raw.split(SPLIT)):
        block = registrant_block(section)

        for label, pat in (
            ("Registrant Organization",
             r"^\s*registrant\s+organi[sz]ation\s*:\s*(.+?)\s*$"),
            ("Registrant Org",
             r"^\s*registrant\s+org(?:\s|-)?(?:name)?\s*:\s*(.+?)\s*$"),
        ):
            m = re.search(pat, section, re.I | re.M)
            if m and (org := clean_org(m.group(1))):
                return org, label

        for label, pat in (
            ("Organization", r"^\s*organi[sz]ation(?:\s*name)?\s*:\s*(.+?)\s*$"),
            ("Company", r"^\s*(?:company|company\s*name)\s*:\s*(.+?)\s*$"),
            ("org", r"^\s*org(?:-name)?\s*:\s*(.+?)\s*$"),
        ):
            m = re.search(pat, block, re.I | re.M)
            if m and (org := clean_org(m.group(1))):
                return org, label

        for label, pat in (
            ("org", r"^\s*org(?:anization|anisation|-name)?\s*:\s*(.+?)\s*$"),
            ("holder", r"^\s*(?:holder|holder-c|owner|owner-name)\s*:\s*(.+?)\s*$"),
            ("registrant", r"^\s*registrant\s*:\s*(.+?)\s*$"),
            ("descr", r"^\s*descr\s*:\s*(.+?)\s*$"),
        ):
            m = re.search(pat, section, re.I | re.M)
            if m and (org := clean_org(m.group(1))):
                return org, label

        if allow_name:
            for label, pat in (
                ("Registrant Name", r"^\s*registrant\s+name\s*:\s*(.+?)\s*$"),
                ("name", r"^\s*(?:name|person)\s*:\s*(.+?)\s*$"),
            ):
                m = re.search(pat, block if label == "name" else section, re.I | re.M)
                if m and (org := clean_org(m.group(1))):
                    return org, label
    return None, ""


# ---------------------------------------------------------------- rdap

def http_get_json(url, args):
    throttle(hostname(url), args.server_interval)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"})
    with urllib.request.urlopen(req, timeout=args.timeout) as resp:
        return json.loads(resp.read().decode(resp.headers.get_content_charset() or "utf-8", "replace")), resp.geturl()


def ask_rdap(url, args):
    for attempt in range(args.retries + 1):
        try:
            return http_get_json(url, args), ""
        except urllib.error.HTTPError as e:
            if e.code in (404, 400):
                return None, "no rdap record"
            if e.code in (429, 503) and attempt < args.retries:
                time.sleep(args.backoff * (attempt + 1))
                continue
            return None, f"HTTP {e.code}"
        except urllib.error.URLError as e:
            reason = str(getattr(e, "reason", e))
            if attempt < args.retries:
                time.sleep(args.backoff * (attempt + 1))
                continue
            return None, f"connect failed ({reason})"
        except (json.JSONDecodeError, ValueError):
            return None, "bad rdap json"
        except Exception as e:  # noqa: BLE001
            return None, f"error: {type(e).__name__}"
    return None, "unreachable"


def vcard_org(entity, allow_name=True):
    va = entity.get("vcardArray")
    if not (isinstance(va, list) and len(va) > 1 and isinstance(va[1], list)):
        return None, ""
    fn = None
    for item in va[1]:
        if isinstance(item, list) and len(item) >= 4:
            val = item[3]
            if isinstance(val, list):
                val = next((v for v in val if isinstance(v, str) and v.strip()), None)
            if not isinstance(val, str):
                continue
            if item[0] == "org" and (org := clean_org(val)):
                return org, "vcard org"
            if item[0] == "fn" and fn is None:
                fn = clean_org(val)
    return (fn, "vcard fn") if (allow_name and fn) else (None, "")


def find_registrant(obj, allow_name=True):
    if not isinstance(obj, dict):
        return None, ""
    for entity in obj.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in entity.get("roles", []) or []]
        if "registrant" in roles:
            org, field = vcard_org(entity, allow_name)
            if org:
                return org, field
        org, field = find_registrant(entity, allow_name)
        if org:
            return org, field
    return None, ""


def registrar_rdap_link(obj):
    for link in obj.get("links", []) or []:
        if str(link.get("rel", "")).lower() == "related" and "rdap" in str(link.get("type", "")).lower():
            href = link.get("href")
            if href and href.startswith("http"):
                return href
    for entity in obj.get("entities", []) or []:
        if "registrar" in [str(r).lower() for r in entity.get("roles", []) or []]:
            for link in entity.get("links", []) or []:
                href = link.get("href", "")
                if href.startswith("http") and "rdap" in href.lower():
                    return href
    return None


def query_rdap(domain, args):
    servers = ["rdap.org"]
    result, problem = ask_rdap(RDAP_BOOTSTRAP.format(domain), args)
    if problem:
        return "", problem, servers
    obj, final_url = result
    servers = [hostname(final_url)]
    raw = json.dumps(obj, indent=2)

    if find_registrant(obj, args.allow_name)[0]:
        return raw, "", servers

    link = registrar_rdap_link(obj)
    if not link:
        return raw, "", servers
    result2, problem2 = ask_rdap(link, args)
    host = hostname(link)
    servers.append(host)
    if problem2:
        return raw, f"referral {host}: {problem2}", servers
    obj2, _ = result2
    return raw + SPLIT + host + " =====\n" + json.dumps(obj2, indent=2), "", servers


def parse_rdap_org(raw, allow_name=True):
    if not raw:
        return None, ""
    for section in reversed(raw.split(SPLIT)):
        start = section.find("{")
        if start < 0:
            continue
        try:
            obj = json.loads(section[start:])
        except (json.JSONDecodeError, ValueError):
            continue
        org, field = find_registrant(obj, allow_name)
        if org:
            return org, field
    return None, ""


# ---------------------------------------------------------------- driver

def classify(org, raw, problem, servers, backend):
    if problem:
        return problem
    if org:
        return "privacy/proxy provider" if PROXY_RE.search(org) else ""
    if NOT_FOUND_RE.search(raw) and backend == "whois":
        return "no whois record"
    if REDACTED_RE.search(registrant_block(raw) if backend == "whois" else raw):
        return "org redacted"
    if len(servers) == 1:
        if backend == "whois" and REFERRAL_RE.search(raw):
            return "thin registry record (referral not followed)"
        if backend == "rdap":
            return "thin rdap record (no registrar referral)"
    return "org field absent"

def run_backend(domain, backend, args):
    """One full query+parse against one backend. Returns a dict."""
    if backend == "whois":
        raw, problem, servers = query_whois(domain, args)
        org, field = parse_whois_org(raw, args.allow_name)
    else:
        raw, problem, servers = query_rdap(domain, args)
        org, field = parse_rdap_org(raw, args.allow_name)

    if args.save_raw:
        os.makedirs(args.save_raw, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
        ext = ".json" if backend == "rdap" else ".txt"
        with open(os.path.join(args.save_raw, safe + ext), "w", encoding="utf-8") as fh:
            fh.write(raw)

    return {"backend": backend, "raw": raw, "problem": problem, "servers": servers,
            "org": org, "field": field,
            "status": classify(org, raw, problem, servers, backend)}


def resolved(a):
    """True only if we got a real org that isn't a privacy proxy."""
    return bool(a["org"]) and a["status"] != "privacy/proxy provider"


def pick(attempts):
    for a in attempts:
        if resolved(a):
            return a
    for a in attempts:          # a proxy name beats nothing
        if a["org"]:
            return a
    return attempts[0]


def whois_usable(args):
    """Installed, and either healthy or due for a recovery probe."""
    global _since_switch
    if not args._have_whois:
        return False
    with _mode_lock:
        if not _forced_rdap:
            return True
        if args.probe_every <= 0:
            return False
        _since_switch += 1
        return _since_switch % args.probe_every == 0


def note_whois_health(attempt, args):
    """Trip the switch only on a RUN of structural failures; recover on any reply."""
    global _whois_failures, _forced_rdap, _since_switch
    prob = attempt["problem"] or ""
    structural = bool(WHOIS_DEAD_RE.search(prob)) and not prob.startswith(REFERRAL_PROBLEM_PREFIX)
    alive = bool(attempt["org"]) or not structural
    with _mode_lock:
        if alive:
            _whois_failures = 0
            if _forced_rdap:
                _forced_rdap, _since_switch = False, 0
                print("** whois responding again -- resuming whois **",
                      file=sys.stderr, flush=True)
            return
        _whois_failures += 1
        if _whois_failures >= args.switch_after and not _forced_rdap:
            _forced_rdap = True
            print(f"** {_whois_failures} consecutive whois failures -- "
                  f"switching to RDAP **", file=sys.stderr, flush=True)


def process(domain, args):
    global _whois_failures, _forced_rdap

    primary = args.backend
    if primary == "auto":
        primary = "whois" if whois_usable(args) else "rdap"

    attempts = [run_backend(domain, primary, args)]
    if primary == "whois" and args.backend == "auto":
        note_whois_health(attempts[0], args)

    if args.fallback and not resolved(attempts[0]):
        other = "rdap" if primary == "whois" else "whois"
        if other == "rdap" or whois_usable(args):
            attempts.append(run_backend(domain, other, args))
            if other == "whois" and args.backend == "auto":
                note_whois_health(attempts[1], args)

    best = pick(attempts)
    status = best["status"]
    if len(attempts) > 1 and not best["org"]:
        status = f"{status}; {attempts[1]['backend']}: {attempts[1]['status']}"

    match = bool(best["org"]) and any(n in norm(best["org"]) for n in args._org_norm)
    if match and status == "privacy/proxy provider":
        status = ""

    return {"domain": domain, "registrant_org": best["org"] or "", "field": best["field"],
            "match": match, "source": f"{best['backend']}:{best['servers'][-1]}",
            "status": status}

def use_colour(mode):
    """ANSI on a terminal, off when piped or redirected, unless overridden."""
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    if mode == "always":
        return True
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def load_domains(path):
    out, seen, bad = [], set(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            d = re.sub(r"^\w+://", "", d).split("/")[0].split("?")[0]
            d = d.split("@")[-1].split(":")[0].strip().strip(".")
            if not d:
                continue
            try:
                d = d.encode("idna").decode("ascii")
            except (UnicodeError, UnicodeDecodeError):
                pass
            if not DOMAIN_RE.match(d):
                bad.append(d)
                continue
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out, bad


def main():
    ap = argparse.ArgumentParser(description="Report registrant Organization for a list of domains.")
    ap.add_argument("-l", "--list", dest="domains_file", required=True, metavar="FILE",
                    help="File of domains to check, one per line")
    ap.add_argument("-o", "--out", default="valid_domains.txt",
                    help="Write matching domains, one per line (default valid_domains.txt)")
    ap.add_argument("--org", action="append", metavar="STRING",
                    help="Organization to match, case/punctuation-insensitive substring. "
                         "Repeatable. Default: International Business Machines Corporation")
    ap.add_argument("--backend", choices=["auto", "whois", "rdap"], default="auto")
    ap.add_argument("--fallback", action=argparse.BooleanOptionalAction, default=None,
                    help="If one backend yields no registrant org, retry the domain on "
                         "the other backend. On by default in auto mode; off when "
                         "--backend names one explicitly.")
    ap.add_argument("--switch-after", type=int, default=5,
                    help="In auto mode, switch to RDAP after N CONSECUTIVE whois "
                         "connection failures (any live reply resets the count)")
    ap.add_argument("--probe-every", type=int, default=25, metavar="N",
                    help="After switching to RDAP, retry whois every Nth domain to "
                         "see if it recovered; 0 disables (default 25)")
    ap.add_argument("--max-referrals", type=int, default=3,
                    help="Whois referral hops to follow (default 3)")
    ap.add_argument("--allow-name", action=argparse.BooleanOptionalAction, default=True,
                    help="Fall back to registrant Name when Organization is absent (default on)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--server-interval", type=float, default=2.0,
                    help="Min seconds between queries to the SAME server (default 2)")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--backoff", type=float, default=10.0)
    ap.add_argument("--matches-only", action="store_true")
    ap.add_argument("--color", "--colour", dest="color",
                    choices=["auto", "always", "never"], default="auto",
                    help="Colourise matches in the terminal (default auto: on "
                         "only when stdout is a tty). NO_COLOR is honoured.")
    ap.add_argument("--save-raw", metavar="DIR")
    ap.add_argument("--report", metavar="FILE",
                    help="TSV of every domain with org, source field and status")
    args = ap.parse_args()

    args.org = args.org or ["International Business Machines Corporation"]
    args._org_norm = [n for n in (norm(o) for o in args.org) if n]
    if not args._org_norm:
        sys.exit("error: --org is empty after normalization.")

    if args.fallback is None:
        args.fallback = args.backend == "auto"

    args._have_whois = bool(shutil.which("whois"))
    if args.backend in ("auto", "whois") and not args._have_whois:
        if args.backend == "whois":
            sys.exit("error: `whois` not found (apt install whois).")
        print("note: `whois` not found, using RDAP only", file=sys.stderr)
        args.backend = "rdap"

    domains, bad = load_domains(args.domains_file)
    if bad:
        print(f"note: skipped {len(bad)} unparseable line(s), e.g. {bad[0]!r}", file=sys.stderr)
    if not domains:
        sys.exit("error: nothing to do.")

    colour = use_colour(args.color)
    hits, done = 0, 0
    rows = []
    with open(args.out, "w", encoding="utf-8") as out_fh, \
         ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(process, d, args) for d in domains]
        for fut in as_completed(futures):
            r = fut.result()
            rows.append(r)
            done += 1
            if r["match"]:
                hits += 1
                out_fh.write(r["domain"] + "\n")
                out_fh.flush()
            if r["match"] or not args.matches_only:
                dom, org = f"{r['domain']:<38}", r["registrant_org"] or "-"
                mark = "   <== MATCH" if r["match"] else ""
                note = f"   ({r['status']})" if r["status"] else ""
                if colour:
                    if r["match"]:
                        dom = f"{GREEN}{dom}{RESET}"
                        org = f"{GREEN}{BOLD}{org}{RESET}"
                        mark = f"{GREEN}{BOLD}{mark}{RESET}"
                    if note:
                        note = f"{DIM}{note}{RESET}"
                print(f"[{done}/{len(domains)}] {dom} {org}{mark}{note}", flush=True)

    if args.report:
        order = {d: i for i, d in enumerate(domains)}
        rows.sort(key=lambda r: order[r["domain"]])
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write("domain\tmatch\tregistrant_org\tfield\tsource\tstatus\n")
            for r in rows:
                fh.write("\t".join([r["domain"], "YES" if r["match"] else "no",
                                    r["registrant_org"], r["field"], r["source"], r["status"]]) + "\n")

    unresolved = sum(1 for r in rows if r["status"])
    print(f"\n{hits}/{len(rows)} matched {args.org}. {unresolved} unresolved. Wrote {args.out}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
