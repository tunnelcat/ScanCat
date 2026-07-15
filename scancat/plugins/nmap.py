"""nmap scan modules.

Each scan mode is its own module (nmap-ping, nmap-fast, ...) sharing NmapBase,
so they can be enabled/disabled individually and run concurrently like recon
modules. All modes share one `nmap/` working dir under the subfolder; each
writes its own <mode>.{targets,excludes} inputs and, via -oA, its own
<mode>.{nmap,gnmap,xml} outputs there.

Targets come from the subfolder's *scan* scope: in-scope entries -> targets,
exclusions -> excludes. IP ranges (a.b.c.d-a.b.c.d) are rewritten into nmap's
octet-range notation (10.1-2.3-4.5-6) rather than a pile of CIDRs, which is
exact and far more readable; IPv6 ranges fall back to CIDR summarization.

Raw scans (-sS/-sU/-O/...) need root: when a selected mode requires it and we
aren't root, scancat primes sudo before the run (see scancat.main) and each such
mode is launched as `sudo -n nmap ...`.

adapt() parses each mode's own <mode>.xml into ports + NSE scripts (and the
hosts/ips/resolutions the addresses imply, plus any -O/-A OS match), which the
store upserts like any other module output.
"""
import ipaddress
import json
import shlex
import xml.etree.ElementTree as ET

from .base import ReconModule, Command, normalize_host
from ..store import SubfolderStore

# Applied to every preset mode; the custom mode overrides them with its own.
GLOBAL_FLAGS = ["-vv", "--resolve-all", "--unique"]

# nmap options that require raw sockets (root). Used to decide when to sudo.
ROOT_FLAGS = {
    "-sS", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM",
    "-sO", "-sY", "-sZ", "-O", "-A", "-PO", "-PE", "-PP", "-PM",
}


def _needs_root(flags):
    return any(f in ROOT_FLAGS for f in flags)


def _int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _script_data(elem):
    """Serialize an NSE <script>'s structured <table>/<elem> children to a JSON
    string (dict when every child is keyed, else a list), or None if the script
    only has flat text output."""
    def conv(node):
        kids = [c for c in node if c.tag in ("table", "elem")]
        if not kids:
            return (node.text or "").strip()
        if all(c.get("key") is not None for c in kids):
            return {c.get("key"): conv(c) for c in kids}
        return [conv(c) for c in kids]

    if not [c for c in elem if c.tag in ("table", "elem")]:
        return None
    try:
        return json.dumps(conv(elem))
    except (TypeError, ValueError):
        return None


def _octet_globs(lo, hi):
    """Rewrite an inclusive IPv4 integer range [lo, hi] as a minimal list of
    nmap octet-range expressions (e.g. '10.0.0.1-255', '10.1.2-255.0-255').

    Each expression is a cartesian product of octet specs; to stay a single
    contiguous block it fixes the octets above a 'boundary' octet, ranges the
    boundary octet, and leaves the octets below it full (0-255). We greedily
    take the largest aligned block at each step, so the union is exact."""
    out = []
    while lo <= hi:
        # Largest level L (trailing full octets) with lo aligned and at least
        # one whole block fitting under hi.
        level = 0
        for L in (1, 2, 3):
            block = 256 ** L
            if lo % block == 0 and lo + block - 1 <= hi:
                level = L
        block = 256 ** level
        boundary = 3 - level                 # index of the ranged octet
        a = (lo // block) % 256
        span = (hi - lo + 1) // block        # how many boundary steps fit
        b = min(255, a + span - 1)
        end = lo + (b - a + 1) * block - 1

        octets = [(lo >> (8 * (3 - i))) & 0xFF for i in range(4)]
        parts = []
        for i in range(4):
            if i < boundary:
                parts.append(str(octets[i]))
            elif i == boundary:
                parts.append(str(a) if a == b else f"{a}-{b}")
            else:
                parts.append("0-255")
        out.append(".".join(parts))
        lo = end + 1
    return out


def _expand_targets(rows):
    """Turn scope rows into nmap target lines. Domains/IPs/CIDRs pass through;
    IPv4 ranges become octet-range expressions, IPv6 ranges are summarized into
    CIDRs (nmap's octet trick is IPv4 only). Order-preserving dedup."""
    out = []
    for r in rows:
        if r["kind"] == "range":
            lo, hi = r["value"].split("-", 1)
            a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
            if a.version == 4:
                out.extend(_octet_globs(int(a), int(b)))
            else:
                out.extend(str(n) for n in
                           ipaddress.summarize_address_range(a, b))
        else:
            out.append(r["value"])
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


class NmapBase(ReconModule):
    binary = "nmap"
    module_class = "scan"
    out_datatypes = []       # scan output doesn't feed the recon dependency graph
    output_dir = "nmap"      # every mode writes into the shared nmap/ folder
    flags = []               # per-mode nmap flags
    use_global = True        # prepend GLOBAL_FLAGS (custom mode sets its own)

    def nmap_flags(self):
        return (GLOBAL_FLAGS if self.use_global else []) + list(self.flags)

    def requires_root(self):
        return _needs_root(self.flags)

    def build(self, module_dir, domains):
        # Targets/exclusions come straight from the scan scope, not `domains`
        # (which is only the domain-kind entries).
        store = SubfolderStore(module_dir.parent / "scancat.db")
        rows = store.scope_active("scan")
        targets = _expand_targets([r for r in rows if r["include"]])
        if not targets:
            return []
        excludes = _expand_targets([r for r in rows if not r["include"]])

        # Per-mode input files so concurrent modes in the shared nmap/ dir don't
        # race on a single targets file.
        targets_file = module_dir / f"{self.name}.targets"
        targets_file.write_text("\n".join(targets) + "\n")

        argv = []
        if self.requires_root() and getattr(self.proj, "use_sudo", False):
            argv = ["sudo", "-n"]   # creds primed before the run; fail fast, no hang
        argv += ["nmap"] + self.nmap_flags() + ["-iL", str(targets_file)]
        if excludes:
            excludes_file = module_dir / f"{self.name}.excludes"
            excludes_file.write_text("\n".join(excludes) + "\n")
            argv += ["--excludefile", str(excludes_file)]
        argv += ["-oA", str(module_dir / self.name)]
        return [Command(argv)]

    def adapt(self, module_dir):
        # Parse only this mode's own XML (the nmap/ dir holds every mode's).
        xml_path = module_dir / f"{self.name}.xml"
        if not xml_path.exists():
            return {}
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return {}

        hosts, ips, dns, ports, scripts = [], [], [], [], []
        for host in root.findall("host"):
            addr = version = None
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
                    version = 4 if a.get("addrtype") == "ipv4" else 6
                    break
            if not addr:
                continue

            os_name = os_acc = os_cpe = None
            osmatch = host.find("os/osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")
                os_acc = _int(osmatch.get("accuracy"))
                cpes = [c.text for c in osmatch.findall("osclass/cpe") if c.text]
                os_cpe = json.dumps(cpes) if cpes else None
            ips.append({"address": addr, "version": version, "os_name": os_name,
                        "os_accuracy": os_acc, "os_cpe": os_cpe})

            # Each hostname nmap resolved to this address is a host + resolution.
            for hn in host.findall("hostnames/hostname"):
                name = normalize_host(hn.get("name"))
                if name:
                    hosts.append({"name": name})
                    dns.append({"host": name, "value": addr,
                                "type": "A" if version == 4 else "AAAA"})

            for port in host.findall("ports/port"):
                portid = _int(port.get("portid"))
                if portid is None:
                    continue
                proto = port.get("protocol")
                st = port.find("state")
                svc = port.find("service")
                cpes = [c.text for c in svc.findall("cpe")] if svc is not None else []
                ports.append({
                    "ip": addr, "proto": proto, "port": portid,
                    "state": st.get("state") if st is not None else None,
                    "reason": st.get("reason") if st is not None else None,
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extrainfo": svc.get("extrainfo") if svc is not None else None,
                    "tunnel": svc.get("tunnel") if svc is not None else None,
                    "cpe": json.dumps(cpes) if cpes else None,
                    "conf": _int(svc.get("conf")) if svc is not None else None,
                })
                for s in port.findall("script"):
                    scripts.append({"ip": addr, "proto": proto, "port": portid,
                                    "script_id": s.get("id"),
                                    "output": s.get("output"),
                                    "data": _script_data(s)})

            for s in host.findall("hostscript/script"):
                scripts.append({"ip": addr, "proto": None, "port": None,
                                "script_id": s.get("id"),
                                "output": s.get("output"),
                                "data": _script_data(s)})

        return {"hosts": hosts, "ips": ips, "dns": dns,
                "ports": ports, "scripts": scripts}


class NmapPingModule(NmapBase):
    name = "nmap-ping"
    flags = ["-sn"]


class NmapFastModule(NmapBase):
    name = "nmap-fast"
    flags = ["-F", "--open", "-Pn", "-T4"]


class NmapTcp1000Module(NmapBase):
    name = "nmap-tcp-1000"
    flags = ["-sS", "--top-ports", "1000", "--open", "-Pn", "-T4"]


class NmapTcpAllModule(NmapBase):
    name = "nmap-tcp-all"
    flags = ["-sS", "-p-", "--open", "--defeat-rst-ratelimit", "-Pn", "-T4"]


class NmapUdp1000Module(NmapBase):
    name = "nmap-udp-1000"
    flags = ["-sU", "--top-ports", "1000", "--open", "--defeat-rst-ratelimit",
             "-Pn", "-T4"]


class NmapCustomModule(NmapBase):
    """User-supplied nmap flags (from proj.custom_scan_flags), overriding the
    global flags entirely. Skipped when no flags are set."""
    name = "nmap-custom"
    use_global = False

    def build(self, module_dir, domains):
        raw = (getattr(self.proj, "custom_scan_flags", "") or "").strip()
        self.flags = shlex.split(raw)
        if not self.flags:
            return []
        return super().build(module_dir, domains)


SCAN_MODULES = [
    NmapPingModule,
    NmapFastModule,
    NmapTcp1000Module,
    NmapTcpAllModule,
    NmapUdp1000Module,
    NmapCustomModule,
]


def scan_needs_root(enabled, proj):
    """True if any enabled scan mode needs root (so scancat should prime sudo)."""
    for cls in SCAN_MODULES:
        if cls.name not in enabled:
            continue
        if cls is NmapCustomModule:
            if _needs_root(shlex.split(proj.custom_scan_flags or "")):
                return True
        elif _needs_root(cls.flags):
            return True
    return False
