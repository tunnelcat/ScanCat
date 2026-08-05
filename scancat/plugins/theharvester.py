"""theHarvester OSINT recon, run once per domain."""
import json
import re

from .base import BaseModule, Command, normalize_host, ip_version

SOURCES = ("all")

# theHarvester prints results grouped under "[*] <Section> found: N" headers.
# The values under a section are printed bare; we only surface the ones that
# carry recon value (hosts/ips/emails), tagged per _TH_SECTIONS.
_RE_TH_SECTION = re.compile(r"^\[\*\]\s*(.+?) found:\s*(\d+)", re.I)
# Map a shown section to the notification tag its values get in the TUI.
_TH_SECTIONS = {"hosts": "[+]", "ips": "[+]", "emails": "[*]"}


class TheHarvesterModule(BaseModule):
    name = "theharvester"
    binary = "theHarvester"
    out_datatypes = ["host"]

    # Drop INFO-level logger lines (case-sensitive so a lowercase host like
    # "info.example.com" isn't swept up) and the per-source "[*] Searching X."
    # progress spam. No error/warning wording matching: theHarvester already
    # tags its own lines with [*]/[!], which emit() maps straight onto our
    # scheme - more accurate than guessing from wording.
    HIDE = [r"\bINFO\b", r"^\[\*\]\s*Searching\b"]

    def build(self, module_dir, domains):
        if not domains:
            self.notice("[!] no in-scope domains in the recon scope")
            return []
        commands = []
        for domain in domains:
            filename = f"theHarvester-{domain.replace('.', '-')}"
            argv = ["theHarvester", "-q", "-d", domain, "-b", SOURCES,
                    "-f", str(module_dir / filename)]
            commands.append(Command(argv))
        return commands

    def emit(self, line):
        # Pass theHarvester's own notification markers straight onto ours:
        # [*] -> info, [!] -> warning, [-] -> error. Result values (hosts/ips/
        # emails) are printed bare under a "[*] <Section> found: N" header, so
        # track the section and surface only the useful ones as [+]/[*] data.
        # The ASCII banner and "----" rules fall through to None.
        s = line.strip()
        if s.startswith("[*]"):
            m = _RE_TH_SECTION.match(s)
            if m:
                self._th_tag = _TH_SECTIONS.get(m.group(1).strip().lower())
            return f"[*] {s[3:].strip()}"
        if s.startswith("[!]"):
            return f"[!] {s[3:].strip()}"
        if s.startswith("[-]"):
            return f"[-] {s[3:].strip()}"
        tag = getattr(self, "_th_tag", None)
        if tag and not s.startswith(("[", "*", "-", "=")):
            return f"{tag} {s}"
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
