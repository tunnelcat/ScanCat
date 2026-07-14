"""Scope: the user-authored, editable set of targets a subfolder runs against.

Scope lives in each subfolder's scancat.db (see scancat.store) and is the sole
source of truth for what recon/scanning targets. A target is a domain, IP,
CIDR, or IP range, classified automatically from a single line of text.
Entries can be marked as exclusions and are soft-deleted (never purged) so the
engagement keeps an audit trail.

Two entry paths, both keeping the DB authoritative:
  * `scancat scope add/rm/exclude/list` - quick atomic edits.
  * `scancat scope edit` - dumps the current scope to a temp file, opens
    $EDITOR, and reconciles by diff on save (added lines inserted, removed
    lines soft-deleted, unchanged lines left alone).
"""
import ipaddress
import os
import re
import subprocess
import sys
import tempfile

import questionary

from .plugins.base import FQDN_RE
from .store import SubfolderStore

FORMAT_HINT = ("expected a domain (example.com), IP (10.0.0.5), "
               "CIDR (10.0.0.0/24), or IP range (10.0.0.1-10.0.0.50)")

# All-numeric/dotted junk (256.1.1.1, 10.0.0, 1.2.3.4.5) is almost certainly a
# botched IP, so we say so instead of "unrecognized".
_IPISH_RE = re.compile(r"^[0-9.]+$")
_MAX_DOMAIN_LEN = 253   # RFC 1035


def parse_target(raw):
    """Strictly classify a raw scope line. Returns (result, error):

      * result = (kind, value, start_ip, end_ip) and error = None on success
      * result = None and error = a human-readable reason on rejection

    start_ip/end_ip are numeric bounds for IPv4 kinds so containment ("is this
    discovered IP in scope?") is a plain SQL BETWEEN; they're None for domains
    and IPv6 (whose 128-bit values don't fit SQLite's 64-bit integers)."""
    s = raw.strip()
    if not s:
        return None, "empty target"

    # A '/' means the user meant a network. Host bits are allowed and get
    # normalized to the network address (10.0.0.5/24 -> 10.0.0.0/24).
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None, f"not a valid CIDR: {s!r} ({FORMAT_HINT})"
        return ("cidr", str(net)) + _bounds(net[0], net[-1]), None

    # "a-b" is an IP range only if a side parses as an IP; otherwise it may be a
    # hyphenated domain (foo-bar.com), so fall through rather than erroring.
    if "-" in s:
        lo, _, hi = s.partition("-")
        a, b = _ip_or_none(lo.strip()), _ip_or_none(hi.strip())
        if a is not None and b is not None:
            if a.version != b.version:
                return None, f"IP range {s!r} mixes IPv4 and IPv6"
            if int(a) > int(b):
                return None, f"IP range {s!r} start is after end"
            return ("range", f"{a}-{b}") + _bounds(a, b), None
        if a is not None or b is not None:
            return None, (f"malformed IP range: {s!r} "
                          "(expected a.b.c.d-a.b.c.d)")

    ip = _ip_or_none(s)
    if ip is not None:
        return ("ip", str(ip)) + _bounds(ip, ip), None

    host = s.lower().rstrip(".")
    if len(host) <= _MAX_DOMAIN_LEN and FQDN_RE.match(host):
        return ("domain", host, None, None), None

    if _IPISH_RE.match(s):
        return None, f"not a valid IP address: {s!r}"
    return None, f"unrecognized target: {s!r} ({FORMAT_HINT})"


def classify(raw):
    """Strict classification -> (kind, value, start_ip, end_ip), or None if the
    line isn't a recognizable target. Use parse_target when you also want the
    reason for a rejection."""
    result, _err = parse_target(raw)
    return result


def _ip_or_none(s):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _bounds(a, b):
    return (int(a), int(b)) if a.version == 4 else (None, None)


EDIT_HEADER = """\
# scancat scope for [{sub}]
#
# One target per line. The kind is detected automatically:
#   example.com               a domain
#   10.0.0.5                  a single IP
#   10.0.0.0/24               a CIDR block
#   10.0.0.1-10.0.0.50        an IP range
#
# Exclusions: prefix with '!' to carve a target out of scope
#   !10.0.0.5
#   !admin.example.com
#
# Notes: add "# your note" after a target to annotate it
#   example.com               # client-confirmed
#   !10.0.0.5                 # decommissioned host
#
# Blank lines and lines starting with '#' are ignored.
# On save: lines you removed are disabled (kept for audit), new lines are
# added, and notes are updated to match. Nothing is permanently deleted.
"""


def render_scope_text(sub, entries):
    """Render active scope entries to editable text for `scope edit`."""
    lines = [EDIT_HEADER.format(sub=sub)]
    for group, want_include in (("in scope", True), ("exclusions", False)):
        rows = [e for e in entries if bool(e["include"]) == want_include]
        if not rows:
            continue
        lines.append(f"# --- {group} ---")
        for r in rows:
            prefix = "" if r["include"] else "!"
            note = f"    # {r['note']}" if r["note"] else ""
            lines.append(f"{prefix}{r['value']}{note}")
        lines.append("")
    return "\n".join(lines) + "\n"


def parse_scope_text(text):
    """Parse edited scope text into (desired, invalid): desired is a list of
    (kind, value, include, start_ip, end_ip, note) tuples, invalid is a list of
    (line_number, error) for lines that didn't classify. A leading '!' marks an
    exclusion; text after a '#' on the line is the note."""
    desired, invalid, seen = [], [], set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue                       # blank or full-line comment
        target, sep, note = raw.partition("#")
        target = target.strip()
        note = note.strip() if sep else None
        if not target:
            continue
        include = True
        if target.startswith("!"):
            include, target = False, target[1:].strip()
        result, error = parse_target(target)
        if not result:
            invalid.append((lineno, error))
            continue
        kind, value, start_ip, end_ip = result
        key = (kind, value, include)
        if key in seen:
            continue
        seen.add(key)
        desired.append((kind, value, include, start_ip, end_ip, note or None))
    return desired, invalid


# --- CLI (wired from scancat.main) -------------------------------------------

def cmd_scope(args, proj):
    if not args.scope_cmd:                 # `scancat scope` with no subcommand
        args.scope_parser.print_help()
        return
    existing = proj.existing_subfolders()
    if not existing:
        print("No subfolders in project.")
        return
    action = args.scope_cmd

    if action == "list":
        for sub in _target_subs(proj, args, existing, allow_all=True):
            _print_scope(sub, _store_for(proj, sub))
        return

    subs = _target_subs(proj, args, existing, allow_all=False)
    if action == "edit":
        if len(subs) != 1:
            raise SystemExit("scope edit works on one subfolder; use --sub SUB.")
        _scope_edit(proj, subs[0])
    elif action in ("add", "exclude"):
        for sub in subs:
            _scope_add(proj, sub, args.value, include=(action == "add"),
                       note=args.note)
    elif action == "rm":
        for sub in subs:
            _scope_rm(proj, sub, args.value)


def _warn(sub, msg):
    print(f"[{sub}] error: {msg}", file=sys.stderr)


def _store_for(proj, sub):
    """Open (creating if needed) a subfolder's datastore."""
    store = SubfolderStore(proj.subfolder_path(sub) / "scancat.db")
    store.init()
    return store


def ensure_scope(proj, subfolders):
    """For each in-scope subfolder, make sure it has domain targets to work on.
    Any without are offered the scope editor. Returns the subfolders that end
    up with in-scope domains (what recon can actually run against)."""
    active = []
    for sub in subfolders:
        store = _store_for(proj, sub)
        if not store.scope_domains():
            print(f"[!] [{sub}] has no domains in scope.")
            if questionary.confirm(f"[{sub}] Edit scope now?",
                                   default=True).ask():
                _scope_edit(proj, sub)
        if store.scope_domains():
            active.append(sub)
        else:
            print(f"[!] [{sub}] skipped - set targets with "
                  f"'scancat scope add <target> --sub {sub}'")
    return active


def _target_subs(proj, args, existing, allow_all):
    """Resolve which subfolders a scope command targets. --sub selects
    explicitly (repeatable, comma-separated); otherwise mutating commands
    require a single unambiguous subfolder while `list` defaults to all."""
    if getattr(args, "sub", None):
        wanted = [x.strip() for s in args.sub for x in s.split(",") if x.strip()]
        bad = [s for s in wanted if s not in existing]
        if bad:
            raise SystemExit(f"Unknown subfolder(s): {', '.join(bad)}")
        return wanted
    if allow_all:
        in_scope = [s for s in (proj.scope or existing) if s in existing]
        return in_scope or existing
    if len(existing) == 1:
        return existing
    raise SystemExit("Multiple subfolders; pick one with --sub SUB "
                     f"(choices: {', '.join(existing)}).")


def _scope_add(proj, sub, values, include, note):
    store = _store_for(proj, sub)
    for raw in values:
        result, error = parse_target(raw)
        if not result:
            _warn(sub, error)
            continue
        kind, value, start_ip, end_ip = result
        store.scope_set(kind, value, include=include, note=note,
                        start_ip=start_ip, end_ip=end_ip)
        print(f"[{sub}] {'in scope' if include else 'excluded'}: {kind} {value}")


def _scope_rm(proj, sub, values):
    store = _store_for(proj, sub)
    for raw in values:
        result, error = parse_target(raw)
        if not result:
            _warn(sub, error)
            continue
        kind, value, _s, _e = result
        n = store.scope_disable(kind, value)
        print(f"[{sub}] {'removed' if n else 'not in scope'}: {kind} {value}")


def _scope_edit(proj, sub):
    store = _store_for(proj, sub)
    fd, tmp = tempfile.mkstemp(prefix=f"scancat-scope-{sub}-", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(render_scope_text(sub, store.scope_active()))
        subprocess.call([os.environ.get("EDITOR", "nano"), tmp])
        with open(tmp) as f:
            desired, invalid = parse_scope_text(f.read())
    finally:
        os.unlink(tmp)
    for lineno, error in invalid:
        _warn(sub, f"line {lineno}: {error}")
    added, removed = store.scope_reconcile(desired)
    msg = f"[{sub}] scope updated: +{added} -{removed}, {len(desired)} active"
    if invalid:
        msg += f", {len(invalid)} invalid line(s) skipped"
    print(msg)


def _print_scope(sub, store):
    rows = store.scope_active()
    if not rows:
        print(f"[{sub}] (no scope)")
        return
    print(f"[{sub}]")
    for r in rows:
        mark = " " if r["include"] else "!"
        note = f"    # {r['note']}" if r["note"] else ""
        print(f"  {mark} {r['kind']:6} {r['value']}{note}")
