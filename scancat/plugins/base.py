"""Base recon module.

A module checks that its tool is installed, runs one or more external
commands (streaming their output to the live display), then extracts FQDNs
from the output and merges them into the subfolder's fqdns-all.txt.
"""
import asyncio
import re
import shutil
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
    """All FQDNs in text that match or are subdomains of the given domains."""
    roots = [d.lower().lstrip(".") for d in domains]
    found = set()
    for match in FQDN_RE.findall(text):
        host = match.lower().rstrip(".")
        for root in roots:
            if host == root or host.endswith("." + root):
                found.add(host)
                break
    return sorted(found)


def merge_into(all_file, fqdns):
    """Merge fqdns into all_file, keeping the file unique and sorted."""
    existing = set()
    if all_file.exists():
        existing = {ln.strip() for ln in all_file.read_text().splitlines()
                    if ln.strip()}
    existing.update(fqdns)
    all_file.write_text("\n".join(sorted(existing)) + ("\n" if existing else ""))


class Command:
    """One external command to run.

    tee   - optional file to also capture stdout into (emulates `| tee`).
    reads - output files to scan for FQDNs once the command finishes.
    """
    def __init__(self, argv, tee=None, reads=None):
        self.argv = argv
        self.tee = tee
        self.reads = reads or []


class ReconModule:
    name = "base"
    binary = None   # external tool required on PATH (None = no check)

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

        display.start(key)
        collected = []
        for cmd in self.build(domains_file, module_dir, domains):
            tee = open(cmd.tee, "w") if cmd.tee else None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd.argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except FileNotFoundError:
                display.missing(key)
                display.log(key, f"[!] failed to launch {cmd.argv[0]}")
                if tee:
                    tee.close()
                return

            async for raw in proc.stdout:
                line = raw.decode(errors="replace").rstrip("\n")
                display.log(key, line)
                if tee:
                    tee.write(line + "\n")
            await proc.wait()
            if tee:
                tee.close()

            for read_file in cmd.reads:
                if Path(read_file).exists():
                    collected.append(Path(read_file).read_text())

        fqdns = extract_fqdns("\n".join(collected), domains)
        (module_dir / f"fqdns-{self.name}.txt").write_text(
            "\n".join(fqdns) + ("\n" if fqdns else "")
        )
        async with lock:
            merge_into(subfolder_dir / "fqdns-all.txt", fqdns)
        display.log(key, f"extracted {len(fqdns)} fqdns")
        display.done(key)
