"""Scope: the user-authored, editable set of targets a subfolder runs against.

Scope lives in each subfolder's scancat.db (see scancat.store) and is the sole
source of truth for what recon/scanning targets. A target is a domain, IP,
CIDR, or IP range, classified automatically from a single line of text.
Entries can be marked as exclusions and are soft-deleted (never purged) so the
engagement keeps an audit trail.

Scope is split by phase (given explicitly on every command):
  * recon - the seed domains subfinder/dnsx expand.
  * scan  - the hosts/IPs nmap actually targets, usually built from recon
            discoveries via `scancat scope expand`, then pruned.

Entry paths, all keeping the DB authoritative:
  * `scancat scope add/rm/exclude/list --phase P` - quick atomic edits.
  * `scancat scope edit --phase P` - dumps the phase's scope to a temp file,
    opens $EDITOR, and reconciles by diff on save.
  * `scancat scope expand` - pulls discovered hosts into the scan phase
    (resolvable-only, minus scan_noise, by default).
  * `scancat scope import --from P --to Q` - copies scope entries between phases.
"""
import fnmatch
import itertools
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
# scancat {phase} scope for [{sub}]
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


def render_scope_text(sub, phase, entries):
    """Render active scope entries to editable text for `scope edit`."""
    lines = [EDIT_HEADER.format(sub=sub, phase=phase)]
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
    """Parse edited scope text into (entries, invalid): entries is a list of
    entry dicts (with a 1-based lineno, not yet deduped/merged), invalid is a
    list of (line_number, error) for lines that didn't classify. A leading '!'
    marks an exclusion; text after a '#' on the line is the note."""
    entries, invalid = [], []
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
        entries.append(_entry(kind, value, include, start_ip, end_ip,
                              note or None, lineno))
    return entries, invalid


def _entry(kind, value, include, start_ip, end_ip, note, lineno=None):
    return {"kind": kind, "value": value, "include": int(bool(include)),
            "start_ip": start_ip, "end_ip": end_ip, "note": note,
            "lineno": lineno}


# --- deduplication + overlap merging -----------------------------------------
# IP/CIDR/range entries carry an integer address interval; domains don't. We
# dedup exact repeats (domains included) and, within a phase+include group,
# collapse overlapping intervals into one encompassing entry, warning about
# everything we change (with line numbers when the entry came from `scope edit`).

def _interval(kind, value):
    """(version, lo, hi) integer address interval for an ip/cidr/range value.
    Works for both IPv4 and IPv6 (Python ints are unbounded)."""
    if kind == "ip":
        ip = ipaddress.ip_address(value)
        return ip.version, int(ip), int(ip)
    if kind == "cidr":
        net = ipaddress.ip_network(value, strict=False)
        return net.version, int(net.network_address), int(net.broadcast_address)
    lo, hi = value.split("-", 1)
    a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
    return a.version, int(a), int(b)


def _canonical_span(lo, hi, version):
    """Represent the interval [lo, hi] as (kind, value, start_ip, end_ip): a
    single CIDR when it's exactly one aligned network, an ip when lo==hi, else
    a range. start/end bounds are stored only for IPv4."""
    first, last = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
    start, end = (lo, hi) if version == 4 else (None, None)
    if lo == hi:
        return "ip", str(first), start, end
    nets = list(ipaddress.summarize_address_range(first, last))
    if len(nets) == 1:
        return "cidr", str(nets[0]), start, end
    return "range", f"{first}-{last}", start, end


def _loc(e):
    return f"{e['value']}" + (f" (line {e['lineno']})" if e["lineno"] else "")


def _merge_ip_overlaps(entries):
    """Collapse overlapping ip/cidr/range entries (per include + IP version).
    Returns (result_entries, warnings)."""
    result, warnings = [], []
    groups = {}
    for e in entries:
        version, lo, hi = _interval(e["kind"], e["value"])
        groups.setdefault((e["include"], version), []).append((lo, hi, e))

    for (include, version), items in groups.items():
        clusters = []
        for lo, hi, e in sorted(items, key=lambda t: (t[0], t[1])):
            if clusters and lo <= clusters[-1]["hi"]:   # overlaps current cluster
                c = clusters[-1]
                c["members"].append(e)
                c["hi"] = max(c["hi"], hi)
            else:
                clusters.append({"lo": lo, "hi": hi, "members": [e]})
        for c in clusters:
            if len(c["members"]) == 1:
                result.append(c["members"][0])
                continue
            kind, value, start, end = _canonical_span(c["lo"], c["hi"], version)
            note = next((m["note"] for m in c["members"] if m["note"]), None)
            result.append(_entry(kind, value, include, start, end, note))
            listed = ", ".join(_loc(m) for m in c["members"])
            warnings.append(f"overlap: merged {listed} -> {value}")
    return result, warnings


def normalize_scope(entries):
    """Dedup and overlap-merge a list of entry dicts. Returns (final, warnings)
    where final is a list of (kind, value, include, start_ip, end_ip, note)
    tuples ready for scope_reconcile."""
    warnings, seen, unique = [], set(), []
    for e in entries:
        key = (e["kind"], e["value"], e["include"])
        if key in seen:
            warnings.append(f"duplicate {_loc(e)} - skipped")
            continue
        seen.add(key)
        unique.append(e)

    iplike = [e for e in unique if e["kind"] in ("ip", "cidr", "range")]
    others = [e for e in unique if e["kind"] not in ("ip", "cidr", "range")]
    merged, mwarn = _merge_ip_overlaps(iplike)
    warnings.extend(mwarn)
    final = [(e["kind"], e["value"], e["include"], e["start_ip"], e["end_ip"],
              e["note"]) for e in others + merged]
    return final, warnings


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

    if action == "expand":
        # expand only ever targets the scan phase, from recon discoveries;
        # defaults to all subfolders, -s narrows it.
        for sub in _target_subs(proj, args, existing, allow_all=True):
            _scope_expand(proj, sub,
                          include_unresolvable=args.include_unresolvable_hosts,
                          include_noise=args.include_scan_noise)
        return

    if action == "import":
        if args.from_phase == args.to_phase:
            raise SystemExit("--from and --to must be different phases")
        for sub in _target_subs(proj, args, existing, allow_all=False):
            _scope_import(proj, sub, args.from_phase, args.to_phase)
        return

    phase = args.phase   # required on every other scope command
    if action == "list":
        for sub in _target_subs(proj, args, existing, allow_all=True):
            _print_scope(sub, _store_for(proj, sub), phase)
        return

    subs = _target_subs(proj, args, existing, allow_all=False)
    if action == "edit":
        if len(subs) != 1:
            raise SystemExit("scope edit works on one subfolder; use --sub SUB.")
        _scope_edit(proj, subs[0], phase)
    elif action in ("add", "exclude"):
        for sub in subs:
            _scope_add(proj, sub, phase, args.value,
                       include=(action == "add"), note=args.note)
    elif action == "rm":
        for sub in subs:
            _scope_rm(proj, sub, phase, args.value)


def _warn(tag, msg):
    print(f"[{tag}] error: {msg}", file=sys.stderr)


def _notify(tag, msg):
    print(f"[{tag}] warning: {msg}", file=sys.stderr)


def _store_for(proj, sub):
    """Open (creating if needed) a subfolder's datastore."""
    store = SubfolderStore(proj.subfolder_path(sub) / "scancat.db")
    store.init()
    return store


def ensure_scope(proj, subfolders):
    """For each in-scope subfolder, make sure it has recon-phase domains to work
    on. Any without are offered the scope editor. Returns the subfolders that
    end up with recon domains (what recon can actually run against)."""
    active = []
    for sub in subfolders:
        store = _store_for(proj, sub)
        if not store.scope_domains("recon"):
            print(f"[!] [{sub}] has no domains in the recon scope.")
            if questionary.confirm(f"[{sub}] Edit recon scope now?",
                                   default=True).ask():
                _scope_edit(proj, sub, "recon")
        if store.scope_domains("recon"):
            active.append(sub)
        else:
            print(f"[!] [{sub}] skipped - set targets with "
                  f"'scancat scope add <target> --phase recon --sub {sub}'")
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


def _scope_add(proj, sub, phase, values, include, note):
    store = _store_for(proj, sub)
    tag = f"{sub}/{phase}"
    new = []
    for raw in values:
        result, error = parse_target(raw)
        if not result:
            _warn(tag, error)
            continue
        kind, value, start_ip, end_ip = result
        new.append(_entry(kind, value, include, start_ip, end_ip, note))
    if not new:
        return
    # Normalize against what's already in the phase so a new entry that dups or
    # overlaps an existing one is caught (existing first, so it wins on dedup).
    existing = [_entry(r["kind"], r["value"], r["include"], r["start_ip"],
                       r["end_ip"], r["note"]) for r in store.scope_active(phase)]
    final, warnings = normalize_scope(existing + new)
    for w in warnings:
        _notify(tag, w)
    added, removed = store.scope_reconcile(phase, final)
    verb = "in scope" if include else "excluded"
    print(f"[{sub}/{phase}] {verb}: +{added} -{removed}")


def _scope_rm(proj, sub, phase, values):
    store = _store_for(proj, sub)
    tag = f"{sub}/{phase}"
    for raw in values:
        result, error = parse_target(raw)
        if not result:
            _warn(tag, error)
            continue
        kind, value, _s, _e = result
        n = store.scope_disable(phase, kind, value)
        state = "removed" if n else "not in scope"
        print(f"[{sub}/{phase}] {state}: {kind} {value}")


def _scope_edit(proj, sub, phase):
    store = _store_for(proj, sub)
    fd, tmp = tempfile.mkstemp(prefix=f"scancat-scope-{sub}-{phase}-", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(render_scope_text(sub, phase, store.scope_active(phase)))
        subprocess.call([os.environ.get("EDITOR", "nano"), tmp])
        with open(tmp) as f:
            entries, invalid = parse_scope_text(f.read())
    finally:
        os.unlink(tmp)
    tag = f"{sub}/{phase}"
    for lineno, error in invalid:
        _warn(tag, f"line {lineno}: {error}")
    final, warnings = normalize_scope(entries)
    for w in warnings:
        _notify(tag, w)
    added, removed = store.scope_reconcile(phase, final)
    msg = (f"[{sub}/{phase}] scope updated: +{added} -{removed}, "
           f"{len(final)} active")
    if invalid:
        msg += f", {len(invalid)} invalid line(s) skipped"
    print(msg)


def _scope_expand(proj, sub, include_unresolvable, include_noise):
    """Pull recon-discovered hosts into the subfolder's scan scope. Skips hosts
    already curated into scan scope (in any state, so removals aren't undone),
    non-resolvable hosts (unless include_unresolvable), and scan_noise matches
    (unless include_noise)."""
    store = _store_for(proj, sub)
    existing = store.scope_values("scan")
    patterns = [] if include_noise else proj.scan_noise

    added = skipped_noise = skipped_unresolvable = skipped_existing = 0
    for host, resolvable in store.discovered_hosts():
        if host in existing:
            skipped_existing += 1
            continue
        if any(fnmatch.fnmatch(host, pat) for pat in patterns):
            skipped_noise += 1
            continue
        if not include_unresolvable and resolvable != 1:
            skipped_unresolvable += 1
            continue
        store.scope_set("scan", "domain", host)
        added += 1

    parts = [f"added {added}"]
    if skipped_noise:
        parts.append(f"skipped {skipped_noise} (scan_noise)")
    if skipped_unresolvable:
        parts.append(f"skipped {skipped_unresolvable} (unresolvable)")
    if skipped_existing:
        parts.append(f"skipped {skipped_existing} (already in scan scope)")
    print(f"[{sub}/scan] expand: " + ", ".join(parts))


def _scope_import(proj, sub, from_phase, to_phase):
    """Copy active scope entries (targets and exclusions, with their notes)
    from one phase into another. Values already present in the destination
    (in any state) are skipped, so a re-import doesn't undo curation there."""
    store = _store_for(proj, sub)
    existing = store.scope_values(to_phase)
    added = skipped = 0
    for r in store.scope_active(from_phase):
        if r["value"] in existing:
            skipped += 1
            continue
        store.scope_set(to_phase, r["kind"], r["value"],
                        include=bool(r["include"]), note=r["note"],
                        start_ip=r["start_ip"], end_ip=r["end_ip"])
        added += 1
    parts = [f"added {added}"]
    if skipped:
        parts.append(f"skipped {skipped} (already in {to_phase} scope)")
    print(f"[{sub}/{to_phase}] import from {from_phase}: " + ", ".join(parts))


def _print_scope(sub, store, phase=None):
    """Print a subfolder's scope, grouped by phase. With phase given, only that
    phase; otherwise every phase that has entries."""
    rows = store.scope_active(phase)
    if not rows:
        print(f"[{sub}/{phase}] (no scope)" if phase else f"[{sub}] (no scope)")
        return
    for ph, group in itertools.groupby(rows, key=lambda r: r["phase"]):
        print(f"[{sub}/{ph}]")
        for r in group:
            mark = " " if r["include"] else "!"
            note = f"    # {r['note']}" if r["note"] else ""
            print(f"  {mark} {r['kind']:6} {r['value']}{note}")
