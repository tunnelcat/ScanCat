"""httpx web-probe module (vuln phase).

Probes the host:port candidates gathered by recon/scan and records which ones
actually serve HTTP/HTTPS. The url list (urlTargets-out.txt) feeds the web
modules - nuclei-web, and gowitness before it.
"""
from .base import BaseModule, Command
from ..store import SubfolderStore


class HttpxModule(BaseModule):
    """Probe every host:port candidate from the datastore (nmap's open TCP
    ports, expanded to each hostname that resolves to the IP) and keep the ones
    that actually speak HTTP/HTTPS as full URLs."""
    name = "httpx"
    binary = "httpx"
    module_class = "vuln"
    out_datatypes = ["url"]

    # With -silent, every httpx stdout line is a discovered URL.
    FIND = [(r"^(https?://\S+)", "[+] {0}")]

    def build(self, module_dir, domains):
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
        argv = ["httpx", "-l", str(in_file), "-silent", "-nc",
                "-o", str(out_file)]
        return [Command(argv)]
