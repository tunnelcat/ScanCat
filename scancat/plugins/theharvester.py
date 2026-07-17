"""theHarvester OSINT recon, run once per domain."""
import json
import re

from .base import (ReconModule, Command, normalize_host, ip_version,
                   notify_failure)

SOURCES = ("all")

# theHarvester prints results grouped under "[*] <Section> found: N" headers.
# We only surface the sections that carry recon value; the rest (ASNs, urls,
# social handles, ...) plus the banner and per-source progress are dropped.
_RE_TH_SECTION = re.compile(r"^\[\*\]\s*(.+?) found:\s*(\d+)", re.I)
_RE_TH_SEARCH = re.compile(r"^\[\*\]\s*Searching\b", re.I)
# Logger lines carry an uppercase level token; drop the INFO ones. Case matters
# so a lowercase host like "info.example.com" isn't swept up with them.
_RE_TH_INFO = re.compile(r"\bINFO\b")
# Map a shown section to the notification tag its values get in the TUI.
_TH_SECTIONS = {"hosts": "[+]", "ips": "[+]", "emails": "[*]"}


class TheHarvesterModule(ReconModule):
    name = "theharvester"
    binary = "theHarvester"
    out_datatypes = ["host"]

    def build(self, module_dir, domains):
        commands = []
        for domain in domains:
            filename = f"theHarvester-{domain.replace('.', '-')}"
            argv = ["theHarvester", "-q", "-d", domain, "-b", SOURCES,
                    "-f", str(module_dir / filename)]
            commands.append(Command(argv))
        return commands

    def display_line(self, line):
        # theHarvester is chatty: an ASCII banner, a "[*] Searching X." line per
        # source, and result sections split by "----" rules. Track the current
        # section from its "found:" header and only echo values under the ones
        # worth showing (hosts/ips/emails); suppress everything else.
        stripped = line.strip()
        if not stripped:
            return None
        if _RE_TH_INFO.search(stripped):   # suppress INFO-level log lines
            return None
        m = _RE_TH_SECTION.match(stripped)
        if m:
            name = m.group(1).strip()
            self._th_tag = _TH_SECTIONS.get(name.lower())
            if self._th_tag:
                return f"[*] {name} found: {m.group(2)}"
            return None
        if _RE_TH_SEARCH.match(stripped):
            self._th_tag = None   # new search phase: no result section is active
            return None
        # Error/failure wording always wins, even inside a surfaced section, so
        # a stray failure line isn't mislabeled as a finding.
        failure = notify_failure(stripped)
        if failure:
            return failure
        # Value line: only shown while inside a surfaced section. Header/banner
        # lines never reach here as data because no section is active yet.
        tag = getattr(self, "_th_tag", None)
        if tag and not stripped.startswith(("[", "*", "-", "=")):
            return f"{tag} {stripped}"
        return None

    def adapt(self, module_dir):
        # Deduplication is the datastore's job (unique keys + upsert), so this
        # just emits every valid record it sees.
        hosts, ips, dns, emails = [], [], [], []

        def add_ip(addr):
            ver = ip_version(addr)
            if ver:
                ips.append({"address": addr, "version": ver})
            return ver

        for out_file in module_dir.glob("theHarvester-*.json"):
            try:
                data = json.loads(out_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            # The queried domain (theHarvester records its args in "cmd", e.g.
            # "-q -d example.com -b all ...") is the domain that produced these
            # emails, so map them to it.
            parts = (data.get("cmd") or "").split()
            queried = (normalize_host(parts[parts.index("-d") + 1])
                       if "-d" in parts and parts.index("-d") + 1 < len(parts)
                       else None)
            for entry in data.get("hosts", []):
                # entries may be "host", "host:ip", or "host:ipv6"
                host_part, _, ip_part = entry.partition(":")
                host = normalize_host(host_part)
                if not host:
                    continue
                hosts.append({"name": host})
                ip = ip_part.strip()
                ver = ip_version(ip) if ip else None
                if ver:
                    # Host-linked ip: the store's A/AAAA handling upserts it into
                    # ips + resolutions, so no separate ips entry is needed here.
                    dns.append({"host": host, "type": "A" if ver == 4 else "AAAA",
                                "value": ip})
            for addr in data.get("ips", []):
                add_ip(addr.strip())   # standalone ips (no host) still need this
            for em in data.get("emails", []):
                em = em.strip().lower()
                if em and "@" in em:
                    emails.append({"address": em, "host": queried})

        return {"hosts": hosts, "ips": ips, "dns": dns, "emails": emails}
