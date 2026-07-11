"""Base recon module.

A module checks that its tool is installed, then runs one or more external
commands, streaming their output to the live display and a per-module log.
"""
import asyncio
import shutil
from datetime import datetime
from pathlib import Path


def read_domains(domains_file):
    """Domains from a domains.txt (strips blanks and # comments)."""
    lines = Path(domains_file).read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


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
    binary = None   # external tool required on PATH (None = no check)

    def build(self, domains_file, module_dir, domains):
        """Return the list of Command objects to run. Override in subclasses."""
        raise NotImplementedError

    async def run(self, key, display, proj, sub):
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
                    )
                except FileNotFoundError:
                    display.missing(key)
                    display.log(key, f"[!] failed to launch {cmd.argv[0]}")
                    mlog.write(f"[!] failed to launch {cmd.argv[0]}")
                    if tee:
                        tee.close()
                    return

                try:
                    async for raw in proc.stdout:
                        line = raw.decode(errors="replace").rstrip("\n")
                        display.log(key, line)
                        mlog.write(line)
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

            display.done(key)
        finally:
            mlog.close()
