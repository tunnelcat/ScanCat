"""Base recon module.

A module checks that its tool is installed, runs one or more external
commands (streaming their output to the live display), then extracts FQDNs
from the output and merges them into the subfolder's fqdns-all.txt.
"""
import asyncio
import re
import shutil
from datetime import datetime
from pathlib import Path

# Broad FQDN matcher; results are then filtered to the in-scope domains so we
# only keep hosts that are (or are subdomains of) something in domains.txt.
FQDN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)


def read_domains(domains_file):
    """Domains from a domains.txt (strips blanks and # comments)."""
    lines = Path(domains_file).read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def extract_fqdns(text, domains):
    """All FQDNs in text that match or are subdomains of the given domains.
    Always lowercase, so results stay normalized regardless of tool casing.
    """
    roots = [d.lower().lstrip(".") for d in domains]
    found = set()
    for match in FQDN_RE.findall(text):
        host = match.lower().rstrip(".")
        for root in roots:
            if host == root or host.endswith("." + root):
                found.add(host)
                break
    return sorted(found)


def read_fqdns(path):
    """Unique, lowercase fqdns from a file (empty set if it doesn't exist)."""
    path = Path(path)
    if not path.exists():
        return set()
    return {ln.strip().lower() for ln in path.read_text().splitlines() if ln.strip()}


def write_fqdns(path, fqdns):
    """Write fqdns to path, sorted and unique."""
    Path(path).write_text("\n".join(sorted(fqdns)) + ("\n" if fqdns else ""))


def merge_module_file(module_file, fqdns):
    """Append fqdns into module_file, then rewrite it deduped and sorted."""
    merged = read_fqdns(module_file)
    merged.update(fqdns)
    write_fqdns(module_file, merged)
    return merged


FQDNS_TAG = "fqdns"


def rebuild_fqdns_all(subfolder_dir):
    """Union every fqdns-tagged module's fqdns-<module>.txt into the
    subfolder's fqdns-all.txt, deduped and sorted. Only modules that declare
    FQDNS_TAG in their modular_outputs contribute."""
    all_fqdns = set()
    for module_name in ReconModule.modules_tagged(FQDNS_TAG):
        module_file = subfolder_dir / module_name / f"fqdns-{module_name}.txt"
        all_fqdns.update(read_fqdns(module_file))
    write_fqdns(subfolder_dir / "fqdns-all.txt", all_fqdns)


class Command:
    """One external command to run. Its stdout is always captured for FQDN
    extraction (no output file needed).

    tee   - optional file to also capture stdout into (emulates `| tee`).
    reads - additional output files to scan for FQDNs, if the tool insists
            on writing its own (rather than just using stdout).
    """
    def __init__(self, argv, tee=None, reads=None):
        self.argv = argv
        self.tee = tee
        self.reads = reads or []


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
    binary = None   # external tool required on PATH (None = no check)
    modular_outputs = []   # output tags this module contributes to, e.g. ["fqdns"]

    _registry = []   # every ReconModule subclass, auto-populated below

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        ReconModule._registry.append(cls)

    @classmethod
    def modules_tagged(cls, tag):
        """Names of all registered modules whose modular_outputs include tag."""
        return [m.name for m in ReconModule._registry if tag in m.modular_outputs]

    def build(self, domains_file, module_dir, domains):
        """Return the list of Command objects to run. Override in subclasses."""
        raise NotImplementedError

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
        collected = []
        try:
            for cmd in self.build(domains_file, module_dir, domains):
                tee = open(cmd.tee, "w") if cmd.tee else None
                mlog.write(f"$ {' '.join(cmd.argv)}")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd.argv,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                except FileNotFoundError:
                    display.missing(key)
                    display.log(key, f"[!] failed to launch {cmd.argv[0]}")
                    mlog.write(f"[!] failed to launch {cmd.argv[0]}")
                    if tee:
                        tee.close()
                    return

                stdout_lines = []
                try:
                    async for raw in proc.stdout:
                        line = raw.decode(errors="replace").rstrip("\n")
                        display.log(key, line)
                        mlog.write(line)
                        stdout_lines.append(line)
                        if tee:
                            tee.write(line + "\n")
                    await proc.wait()
                    if proc.returncode:
                        mlog.write(f"[!] exited with code {proc.returncode}")
                        display.log(key, f"[!] exited with code {proc.returncode}")
                except asyncio.CancelledError:
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
                    if tee:
                        tee.close()

                collected.append("\n".join(stdout_lines))
                for read_file in cmd.reads:
                    if Path(read_file).exists():
                        collected.append(Path(read_file).read_text())

            fqdns = extract_fqdns("\n".join(collected), domains)
            merge_module_file(module_dir / f"fqdns-{self.name}.txt", fqdns)
            async with lock:
                rebuild_fqdns_all(subfolder_dir)
            display.log(key, f"extracted {len(fqdns)} fqdns")
            mlog.write(f"extracted {len(fqdns)} fqdns")
            display.done(key)
        finally:
            mlog.close()
