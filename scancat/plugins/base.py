"""Base recon module.

A module checks that its tool is installed, then runs one or more external
commands, streaming their output to the live display and a per-module log.
"""
import asyncio
import ipaddress
import os
import re
import shutil
import signal
from datetime import datetime

from ..store import SubfolderStore

# A valid FQDN/subdomain: one or more dot-separated labels (alphanumeric,
# hyphens allowed but not leading/trailing) followed by an alphabetic TLD.
# Rejects wildcards (*.example.com) and other malformed entries.
FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_host(host):
    """Lowercase/strip a hostname and return it only if it's a valid FQDN
    (rejects wildcards and malformed entries); otherwise None. Adapters use
    this so only clean domains reach the datastore."""
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    return host if host and FQDN_RE.match(host) else None


def ip_version(addr):
    """4 or 6 for a valid IP string, else None."""
    try:
        return ipaddress.ip_address(addr).version
    except ValueError:
        return None


# Unique key per intermediate list, matching the datastore's UNIQUE constraints.
# Used to collapse an adapter's duplicate rows before they reach the DB - e.g.
# subfinder's -oJ -all output repeats each host once per source that found it.
_RECORD_KEYS = {
    "hosts":  lambda r: r["name"],
    "ips":    lambda r: r["address"],
    "dns":    lambda r: (r["host"], r["type"], r["value"]),
    "emails": lambda r: r["address"],
}


# Opt-in wording sets a module can splice into its own ERROR/WARN buckets (see
# ReconModule) or hand to notify_failure(). Nothing here is applied to any
# module automatically. The inline (?i) makes them case-insensitive; word
# boundaries keep hostnames like "failover.example.com" from tripping them.
COMMON_ERRORS = (
    r"(?i)\b(error|fail(?:ed|ure)?|fatal|exception|traceback|denied|refused|"
    r"timed out|timeout|unable to|cannot|not permitted|quitting)\b",
)
COMMON_WARNINGS = (r"(?i)\bwarn(?:ing)?\b",)

_COMMON_ERROR_RE = [re.compile(p) for p in COMMON_ERRORS]
_COMMON_WARN_RE = [re.compile(p) for p in COMMON_WARNINGS]


def _strip_marker(text):
    """Drop a leading tool status token (e.g. theHarvester's "[!]") so a
    notification tag we add doesn't stack on top of the tool's own."""
    return re.sub(r"^\[.\]\s*", "", text.strip())


def notify_failure(line):
    """Return `line` tagged [-]/[!] if it matches COMMON_ERRORS/COMMON_WARNINGS,
    else None. A convenience for tools that decide severity inside emit() - e.g.
    JSON parsers that only error-check a line once it fails to parse as data -
    rather than through the declarative ERROR/WARN buckets."""
    text = _strip_marker(line)
    if any(rx.search(text) for rx in _COMMON_ERROR_RE):
        return f"[-] {text}"
    if any(rx.search(text) for rx in _COMMON_WARN_RE):
        return f"[!] {text}"
    return None


def dedup_records(records):
    """Return `records` with duplicate rows dropped from each list (first
    occurrence wins, by the list's natural unique key). Relying on the DB's
    ON CONFLICT would still store one row, but it wastes an upsert per duplicate
    and inflates the reported count; dedup here avoids both."""
    out = {}
    for name, rows in records.items():
        key = _RECORD_KEYS.get(name)
        if key is None:
            out[name] = rows
            continue
        seen, deduped = set(), []
        for row in rows:
            k = key(row)
            if k not in seen:
                seen.add(k)
                deduped.append(row)
        out[name] = deduped
    return out


class Command:
    """One external command to run.

    tee - optional file to also capture stdout into (emulates `| tee`).
    """
    def __init__(self, argv, tee=None):
        self.argv = argv
        self.tee = tee


class ModuleLog:
    """Timestamped `<module>.log` of commands run and their output."""
    def __init__(self, path):
        self.file = open(path, "a")

    def write(self, line):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.file.write(f"[{ts}] {line}\n")
        self.file.flush()

    def close(self):
        self.file.close()


class ReconModule:
    name = "base"
    binary = None       # external tool required on PATH (None = no check)
    module_class = "recon"   # pipeline phase: "recon" | "scan" | "vuln"
    out_datatypes = []       # data-type tags produced, e.g. ["host"]
    depends_on = []          # out_datatype tags that must finish (same
                             # subfolder) before this runs; [] = start now
    output_dir = None        # working dir under the subfolder; defaults to
                             # self.name, but modes can share one (e.g. nmap)

    # --- live-display filtering (see display_line) -----------------------
    # Declarative severity buckets: each is a list of regex patterns matched
    # against a raw stdout line, in the fixed order HIDE, ERROR, WARN, INFO;
    # the first bucket to match decides the line - HIDE drops it, the others
    # tag the whole line. Entries are bare patterns, or (pattern, template)
    # pairs whose template formats capture groups and carries its own tag.
    # Nothing is applied unless a module opts in (write patterns, or splice in
    # COMMON_ERRORS / COMMON_WARNINGS). FIND is the same idea for simple
    # findings and is applied by the default emit().
    HIDE = ()    # -> suppressed
    ERROR = ()   # -> [-]
    WARN = ()    # -> [!]
    INFO = ()    # -> [*]
    FIND = ()    # (pattern, "[+] {0}") pairs -> findings, via default emit()

    _BUCKETS = (("HIDE", None), ("ERROR", "[-]"), ("WARN", "[!]"),
                ("INFO", "[*]"))
    _hide = _error = _warn = _info = _find = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Compile each configured bucket once per subclass. An entry is a bare
        # pattern (tag the whole line) or a (pattern, template) pair.
        for attr in ("HIDE", "ERROR", "WARN", "INFO", "FIND"):
            compiled = []
            for entry in getattr(cls, attr):
                pat, tmpl = entry if isinstance(entry, tuple) else (entry, None)
                compiled.append((re.compile(pat), tmpl))
            setattr(cls, "_" + attr.lower(), compiled)

    def build(self, module_dir, domains):
        """Return the list of Command objects to run. `domains` is the
        subfolder's in-scope domains (from the datastore). Override in
        subclasses."""
        raise NotImplementedError

    def adapt(self, module_dir):
        """Adapter hook: normalize this module's raw tool output (json/txt/xml)
        into the common intermediate schema (see scancat.store), which run()
        then upserts into the subfolder datastore. Override in subclasses;
        return {} when there's nothing to contribute."""
        return {}

    def display_line(self, line):
        """Map a raw stdout line to what the live display should show, or None
        to suppress it. Runs the declarative severity buckets in order (HIDE,
        ERROR, WARN, INFO); if none claim the line, defers to emit() for a
        finding. The full raw output is always written to the module log."""
        if not line.strip():
            return None
        for attr, tag in self._BUCKETS:
            for rx, tmpl in getattr(self, "_" + attr.lower()):
                m = rx.search(line)
                if not m:
                    continue
                if tag is None:                     # HIDE: drop it
                    return None
                if tmpl:
                    return tmpl.format(*m.groups())
                return f"{tag} {_strip_marker(line)}"
        return self.emit(line)

    def emit(self, line):
        """Produce a finding line for output the severity buckets didn't claim
        (any tagged string, typically "[+] ..."), or None to suppress it. The
        default applies the FIND rules; override for JSON or stateful tools."""
        for rx, tmpl in self._find:
            m = rx.search(line)
            if m:
                return tmpl.format(*m.groups())
        return None

    async def _persist(self, module_dir, store, lock, key, display, mlog):
        """Adapt the raw output and upsert it into the datastore. Called on
        normal completion and again if the module is cancelled, so an
        interrupted run still saves whatever the tool produced before it
        stopped (see run())."""
        records = self.adapt(module_dir)
        if not records:
            return
        records = dedup_records(records)
        async with lock:
            store.init()
            count = store.upsert(records, tool=self.name)
        display.log(key, f"[*] Upserted {count} records into scancat.db")
        mlog.write(f"[*] Upserted {count} records into scancat.db")

    async def run(self, key, display, proj, sub, lock):
        if self.binary and shutil.which(self.binary) is None:
            display.missing(key)
            display.log(key, f"[-] '{self.binary}' not found on PATH")
            return

        self.proj = proj
        subfolder_dir = proj.subfolder_path(sub)
        module_dir = subfolder_dir / (self.output_dir or self.name)
        module_dir.mkdir(parents=True, exist_ok=True)
        # Scope in scancat.db is the sole source of truth for targets; a module
        # reads its own phase (recon modules -> the recon scope).
        store = SubfolderStore(subfolder_dir / "scancat.db")
        domains = store.scope_domains(self.module_class)

        mlog = ModuleLog(module_dir / f"{self.name}.log")
        mlog.write(f"=== {self.name} started ===")

        display.start(key)
        try:
            for cmd in self.build(module_dir, domains):
                tee = open(cmd.tee, "w") if cmd.tee else None
                mlog.write(f"$ {' '.join(cmd.argv)}")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd.argv,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        # Own process group so a terminal Ctrl+C (sent to the
                        # foreground group) doesn't kill the tool directly - only
                        # scancat's handler decides its fate. A new *group* (not
                        # a new session) keeps the controlling tty, so `sudo -n`
                        # can still find the credentials primed before the run.
                        process_group=0,
                    )
                except FileNotFoundError:
                    display.missing(key)
                    display.log(key, f"[-] failed to launch {cmd.argv[0]}")
                    mlog.write(f"[-] failed to launch {cmd.argv[0]}")
                    if tee:
                        tee.close()
                    return

                display.procs[key] = proc
                try:
                    async for raw in proc.stdout:
                        line = raw.decode(errors="replace").rstrip("\n")
                        shown = self.display_line(line) if line.strip() else None
                        if shown:
                            display.log(key, shown)
                        mlog.write(line)
                        if tee:
                            tee.write(line + "\n")
                    await proc.wait()
                    if proc.returncode:
                        mlog.write(f"[-] exited with code {proc.returncode}")
                        display.log(key, f"[-] exited with code {proc.returncode}")
                except asyncio.CancelledError:
                    # Resume first, in case the module was paused (SIGSTOP):
                    # a stopped process can't act on SIGTERM until continued.
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
                    except (ProcessLookupError, OSError):
                        pass
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                    mlog.write("[!] cancelled")
                    display.log(key, "[!] cancelled")
                    display.cancelled(key)
                    # Salvage whatever the tool wrote before it was stopped.
                    try:
                        await self._persist(module_dir, store, lock, key,
                                            display, mlog)
                    except Exception:
                        pass
                    raise
                finally:
                    display.procs.pop(key, None)
                    if tee:
                        tee.close()

            # Adapter: normalize raw output, then upsert into the subfolder
            # datastore. The lock serializes writes to the shared scancat.db.
            await self._persist(module_dir, store, lock, key, display, mlog)
            display.done(key)
        finally:
            mlog.close()
