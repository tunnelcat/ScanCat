"""httpx web-probe module (vuln phase).

Probes the host:port candidates gathered by recon/scan and records which ones
actually serve HTTP/HTTPS. The url list (urlTargets-out) feeds the web
modules - nuclei-web, and gowitness before it.

Note the binary collision: pip's `httpx` HTTP-client CLI installs as `httpx`
too and often shadows ProjectDiscovery's on PATH. _resolve_httpx() finds the
right one so the module works regardless of PATH order.
"""
import json
import os
import subprocess

from .base import BaseModule, Command, normalize_host, ip_version
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
        in_file = module_dir / "hostPorts-in"
        in_file.write_text("\n".join(candidates) + "\n")

        # -o is the plain URL list (fed to nuclei-web/gowitness); -oa also dumps
        # the json/csv/md formats beside it as urlTargets-out.{json,csv,md}.
        # No .txt on the base, else httpx names the siblings urlTargets-out.txt.json.
        out_file = module_dir / "urlTargets-out"
        argv = [httpx_bin, "-l", str(in_file), "-silent", "-nc",
                "-o", str(out_file), "-oa"]
        return [Command(argv)]

    def adapt(self, module_dir):
        # -oa writes the json sibling next to the plain url list. It's JSONL
        # (one object per line); each is a web endpoint.
        out_file = module_dir / "urlTargets-out.json"
        if not out_file.exists():
            return {}

        hosts, dns, web = [], [], []
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = d.get("url")
            if not url:
                continue
            # "host" is a hostname when we probed name:port, an IP when ip:port;
            # normalize_host keeps only valid FQDNs (IPs -> None).
            host = normalize_host(d.get("host") or "")
            if host:
                hosts.append({"name": host})
                # resolved A/AAAA -> ips + resolutions via the existing dns path.
                for ip in (d.get("a") or []) + (d.get("aaaa") or []):
                    ver = ip_version(ip)
                    if ver:
                        dns.append({"host": host, "value": ip,
                                    "type": "A" if ver == 4 else "AAAA"})
            endpoint_ip = d.get("host_ip")
            if not (endpoint_ip and ip_version(endpoint_ip)):
                endpoint_ip = None
            try:
                port = int(d.get("port"))
            except (TypeError, ValueError):
                port = None
            tech = d.get("tech")
            web.append({
                "url": url, "host": host, "ip": endpoint_ip, "port": port,
                "scheme": d.get("scheme"), "status_code": d.get("status_code"),
                "content_type": d.get("content_type"),
                "content_length": d.get("content_length"),
                "title": d.get("title"), "webserver": d.get("webserver"),
                "tech": json.dumps(tech) if tech else None,
            })
        return {"hosts": hosts, "dns": dns, "web": web}
