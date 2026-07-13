"""Base recon module.

A module checks that its tool is installed, then runs one or more external
commands, streaming their output to the live display and a per-module log.
"""
import asyncio
import os
import re
import shutil
import signal
from datetime import datetime
from pathlib import Path

# A valid FQDN/subdomain: one or more dot-separated labels (alphanumeric,
# hyphens allowed but not leading/trailing) followed by an alphabetic TLD.
# Rejects wildcards (*.example.com) and other malformed entries.
FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def read_domains(domains_file):
    """Domains from a domains.txt (strips blanks and # comments)."""
    lines = Path(domains_file).read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def _normalize_fqdns(fqdns):
    """Lowercase, strip, and filter fqdns to valid subdomains/FQDNs only
    (rejects wildcards and other malformed entries)."""
    normalized = set()
    for f in fqdns:
        host = f.strip().lower().rstrip(".")
        if host and FQDN_RE.match(host):
            normalized.add(host)
    return normalized


def write_fqdns(path, fqdns):
    """Write fqdns to path, lowercased, sorted, unique, and filtered to
    valid subdomains/FQDNs only. Overwrites any existing content - use
    merge_fqdns to add to it instead. Returns the fqdns actually written."""
    normalized = sorted(_normalize_fqdns(fqdns))
    Path(path).write_text("\n".join(normalized) + ("\n" if normalized else ""))
    return normalized


def merge_fqdns(path, fqdns):
    """Add fqdns to path's existing content (so repeated runs accumulate
    rather than overwrite), then rewrite it lowercased, sorted, and unique.
    Returns the newly given fqdns, validated and normalized."""
    path = Path(path)
    existing = set()
    if path.exists():
        existing = {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}
    new_valid = _normalize_fqdns(fqdns)
    write_fqdns(path, existing | new_valid)
    return sorted(new_valid)


def merge_resp(path, host_ips):
    """Accumulate a `host ip,ip` file: merge {host: {ips}} into path's
    existing content, unioning the A records per host. Written one line per
    host, sorted by host with sorted IPs. Sets give uniqueness; the single
    sort at write time is the only ordering pass."""
    path = Path(path)
    merged = {}
    if path.exists():
        for ln in path.read_text().splitlines():
            host, _, ips = ln.strip().partition(" ")
            if host:
                merged[host] = set(filter(None, ips.split(",")))
    for host, ips in host_ips.items():
        merged.setdefault(host, set()).update(ips)
    lines = [f"{host} {','.join(sorted(ips))}"
            for host, ips in sorted(merged.items()) if ips]   # skip valueless
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


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
    module_class = []   # category tags, e.g. ["subdomains"], ["dns"]
    depends_on = []     # class tags that must finish (in the same subfolder)
                        # before this module runs; [] = start immediately

    def build(self, domains_file, module_dir, domains):
        """Return the list of Command objects to run. Override in subclasses."""
        raise NotImplementedError

    def parse_output(self, module_dir):
        """Optional hook: parse this module's raw tool output into a
        normalized fqdns-<tool>.txt. Override in subclasses; returns the
        parsed fqdns, or None if this module has nothing to parse."""
        return None

    async def run(self, key, display, proj, sub, lock):
        if self.binary and shutil.which(self.binary) is None:
            display.missing(key)
            display.log(key, f"[!] '{self.binary}' not found on PATH")
            return

        subfolder_dir = proj.subfolder_path(sub)
        module_dir = subfolder_dir / self.name
        module_dir.mkdir(parents=True, exist_ok=True)
        domains_file = subfolder_dir / "domains.txt"
        domains = read_domains(domains_file)

        mlog = ModuleLog(module_dir / f"{self.name}.log")
        mlog.write(f"=== {self.name} started ===")

        display.start(key)
        try:
            for cmd in self.build(domains_file, module_dir, domains):
                tee = open(cmd.tee, "w") if cmd.tee else None
                mlog.write(f"$ {' '.join(cmd.argv)}")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd.argv,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        # Own session/process group so a terminal Ctrl+C
                        # (sent to the foreground group) doesn't kill the tool
                        # directly - only scancat's handler decides its fate.
                        start_new_session=True,
                    )
                except FileNotFoundError:
                    display.missing(key)
                    display.log(key, f"[!] failed to launch {cmd.argv[0]}")
                    mlog.write(f"[!] failed to launch {cmd.argv[0]}")
                    if tee:
                        tee.close()
                    return

                display.procs[key] = proc
                try:
                    async for raw in proc.stdout:
                        line = raw.decode(errors="replace").rstrip("\n")
                        if line.strip():
                            display.log(key, line)
                        mlog.write(line)
                        if tee:
                            tee.write(line + "\n")
                    await proc.wait()
                    if proc.returncode:
                        mlog.write(f"[!] exited with code {proc.returncode}")
                        display.log(key, f"[!] exited with code {proc.returncode}")
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
                    raise
                finally:
                    display.procs.pop(key, None)
                    if tee:
                        tee.close()

            fqdns = self.parse_output(module_dir)
            if fqdns is not None:
                display.log(key, f"parsed {len(fqdns)} fqdns")
                mlog.write(f"parsed {len(fqdns)} fqdns")
                async with lock:
                    merge_fqdns(subfolder_dir / "fqdns-all.txt", fqdns)
            display.done(key)
        finally:
            mlog.close()
