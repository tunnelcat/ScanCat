"""httpx web-probe module (vuln phase).

Probes the host:port candidates gathered by recon/scan and records which ones
actually serve HTTP/HTTPS. The url list (urlTargets-out.txt) feeds the web
modules - nuclei-web, and gowitness before it.

Note the binary collision: pip's `httpx` HTTP-client CLI installs as `httpx`
too and often shadows ProjectDiscovery's on PATH. _resolve_httpx() finds the
right one so the module works regardless of PATH order.
"""
import os
import subprocess

from .base import BaseModule, Command
from ..store import SubfolderStore

_httpx_bin = None   # memoized resolved path (or "" once we've looked and failed)


def _resolve_httpx():
    """Absolute path to ProjectDiscovery's httpx, or None if it isn't
    installed. Works around pip's httpx client shadowing it: candidates are the
    Go bin dir first, then every httpx on PATH; the PD tool is the one whose
    `-version` exits 0 (pip's client errors out)."""
    global _httpx_bin
    if _httpx_bin is not None:
        return _httpx_bin or None

    gobin = os.environ.get("GOBIN") or os.path.join(
        os.environ.get("GOPATH") or os.path.expanduser("~/go"), "bin")
    candidates = [os.path.join(gobin, "httpx")]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(d, "httpx")
        if cand not in candidates:
            candidates.append(cand)

    _httpx_bin = ""
    for path in candidates:
        if not (os.path.isfile(path) and os.access(path, os.X_OK)):
            continue
        try:
            r = subprocess.run([path, "-version"], capture_output=True,
                               timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:          # PD httpx; pip's client exits non-zero
            _httpx_bin = path
            break
    return _httpx_bin or None


class HttpxModule(BaseModule):
    """Probe every host:port candidate from the datastore (nmap's open TCP
    ports, expanded to each hostname that resolves to the IP) and keep the ones
    that actually speak HTTP/HTTPS as full URLs."""
    name = "httpx"
    binary = None    # resolved in build() (avoids the pip-httpx shadowing)
    module_class = "vuln"
    out_datatypes = ["url"]

    # With -silent, every httpx stdout line is a discovered URL.
    FIND = [(r"^(https?://\S+)", "[+] {0}")]

    def build(self, module_dir, domains):
        httpx_bin = _resolve_httpx()
        if not httpx_bin:
            self.notice("[-] ProjectDiscovery httpx not found on PATH "
                        "(pip's 'httpx' client is a different tool)")
            return []

        # Candidates come from scancat.db (one level up), built from nmap's open
        # ports; no candidates (nothing scanned yet) -> nothing to run.
        store = SubfolderStore(module_dir.parent / "scancat.db")
        candidates = store.http_candidates()
        if not candidates:
            self.notice("[!] no open ports in scancat.db yet - run scan first")
            return []
        in_file = module_dir / "hostPorts-in.txt"
        in_file.write_text("\n".join(candidates) + "\n")

        out_file = module_dir / "urlTargets-out.txt"
        argv = [httpx_bin, "-l", str(in_file), "-silent", "-nc",
                "-o", str(out_file)]
        return [Command(argv)]
