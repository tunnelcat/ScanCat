"""Per-subfolder SQLite datastore.

Each subfolder (int/ext/wapt/...) gets one `scancat.db` that all its modules
upsert into, replacing the old flat fqdns-*.txt files. The schema is normalized
around the entities recon produces - hosts, ips, dns_records, emails - so
repeated module runs update rather than duplicate, and nothing is lost.

Provenance lives in a single `observations` table keyed by (entity, tool): it
records every tool that ever reported a given entity, with a first_seen and
last_seen per tool. Entity rows also carry their own first_seen/last_seen (the
aggregate across all tools). This answers "which tools found this, and when"
without baking tool names into the entity schema.

Modules don't touch SQL. Each module's adapter (its `adapt()` method) turns raw
tool output into the common intermediate schema below, and `upsert()` writes it:

    {
      "hosts":  [{"name": str, "resolvable": bool|None, "status_code": str|None}],
      "ips":    [{"address": str, "version": int|None,
                  "os_name": str|None, "os_accuracy": int|None, "os_cpe": str|None}],
      "dns":    [{"host": str, "type": str, "value": str}],   # A/AAAA/CNAME/...
      "emails": [{"address": str, "host": str|None}],   # host = domain it came from
      "ports":  [{"ip": str, "proto": str, "port": int, "state": str|None,
                  "reason"/"service"/"product"/"version"/"extrainfo"/"tunnel"/
                  "cpe"/"conf": ...}],                  # nmap scan results
      "scripts":[{"ip": str, "proto": str|None, "port": int|None,
                  "script_id": str, "output": str|None, "data": str|None}],
    }

Any key may be omitted. A `dns` row's host is upserted as a host too, so the
hosts table always covers every name referenced by a record. A/AAAA `dns` rows
are stored as `resolutions` (host -> ip): the value is upserted into `ips` and
linked, rather than duplicated as text; other record types go to `dns_records`.
A `scripts` row with a port (ip+proto+port) attaches to that port row; without
one it's a host-level script (port_id NULL).
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    resolvable  INTEGER,          -- 1 = last resolved NOERROR, 0 = not, NULL = unknown
    status_code TEXT,             -- last DNS status_code seen
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ips (
    id          INTEGER PRIMARY KEY,
    address     TEXT NOT NULL UNIQUE,
    version     INTEGER,          -- 4 or 6
    os_name     TEXT,             -- top nmap OS match (-O/-A); NULL until run
    os_accuracy INTEGER,          -- that match's accuracy 0-100
    os_cpe      TEXT,             -- json array of cpe strings
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL,    -- CNAME, MX, NS, TXT, SOA, ... (never A/AAAA)
    value       TEXT NOT NULL,    -- target host or text
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(host_id, record_type, value)
);
CREATE TABLE IF NOT EXISTS resolutions (
    id         INTEGER PRIMARY KEY,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip_id      INTEGER NOT NULL REFERENCES ips(id)   ON DELETE CASCADE,
    first_seen TEXT NOT NULL,     -- an A/AAAA answer: host resolves to ip
    last_seen  TEXT NOT NULL,     --   (A vs AAAA is implied by ips.version)
    UNIQUE(host_id, ip_id)
);
CREATE TABLE IF NOT EXISTS ports (
    id         INTEGER PRIMARY KEY,
    ip_id      INTEGER NOT NULL REFERENCES ips(id) ON DELETE CASCADE,
    proto      TEXT NOT NULL,     -- 'tcp' | 'udp'
    port       INTEGER NOT NULL,
    state      TEXT,              -- open | open|filtered | filtered | ...
    reason     TEXT,              -- syn-ack, no-response, ...
    service    TEXT,              -- service name; the rest are filled by -sV
    product    TEXT,
    version    TEXT,              -- service version string
    extrainfo  TEXT,
    tunnel     TEXT,              -- e.g. ssl
    cpe        TEXT,              -- json array of cpe strings
    conf       INTEGER,           -- service detection confidence 0-10
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(ip_id, proto, port)
);
CREATE TABLE IF NOT EXISTS scripts (
    id         INTEGER PRIMARY KEY,
    ip_id      INTEGER NOT NULL REFERENCES ips(id)   ON DELETE CASCADE,
    port_id    INTEGER REFERENCES ports(id) ON DELETE CASCADE,  -- NULL = host script
    script_id  TEXT NOT NULL,     -- NSE id: 'http-title', 'vulners', ...
    output     TEXT,              -- raw script output
    data       TEXT,              -- structured NSE output as json (nullable)
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
-- COALESCE so host scripts (port_id NULL) still dedup: SQLite treats NULLs as
-- distinct in a plain UNIQUE, which would let them pile up on re-scan.
CREATE UNIQUE INDEX IF NOT EXISTS scripts_uq
    ON scripts(ip_id, COALESCE(port_id, 0), script_id);
CREATE TABLE IF NOT EXISTS emails (
    id         INTEGER PRIMARY KEY,
    address    TEXT NOT NULL UNIQUE,
    host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    entity_type TEXT NOT NULL,    -- 'host'|'ip'|'dns_record'|'resolution'|'email'|'port'|'script'
    entity_id   INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_id, tool)
);
CREATE TABLE IF NOT EXISTS scope (
    id         INTEGER PRIMARY KEY,
    phase      TEXT NOT NULL,      -- 'recon' (seed domains) | 'scan' (nmap targets)
    kind       TEXT NOT NULL,      -- 'domain'|'ip'|'cidr'|'range'
    value      TEXT NOT NULL,      -- canonical form the modules consume
    include    INTEGER NOT NULL DEFAULT 1,  -- 1 = in-scope, 0 = exclusion
    enabled    INTEGER NOT NULL DEFAULT 1,  -- 0 = soft-deleted (kept for audit)
    note       TEXT,
    start_ip   INTEGER,            -- IPv4 numeric bounds for containment tests;
    end_ip     INTEGER,            --   NULL for domains and IPv6
    added_at   TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(phase, kind, value, include)
);
"""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_int(flag):
    """bool -> 1/0, leaving None as None (unknown)."""
    return None if flag is None else int(bool(flag))


class SubfolderStore:
    """Thin wrapper over one subfolder's scancat.db. Connections are opened
    per operation (SQLite handles that cheaply) so it's safe to use from
    different asyncio tasks as long as writes are serialized by the caller's
    per-subfolder lock."""

    def __init__(self, path):
        self.path = Path(path)

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self):
        """Create the schema if it doesn't exist. Idempotent. No migrations:
        during development just delete the scancat.db to pick up schema changes."""
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def host_names(self):
        """All known host names, sorted. Empty if the db doesn't exist yet."""
        if not self.path.exists():
            return []
        with self._connect() as conn:
            return [r[0] for r in
                    conn.execute("SELECT name FROM hosts ORDER BY name")]

    def upsert(self, records, tool, when=None):
        """Insert or update the intermediate `records` under provenance `tool`.
        Returns the number of entity rows touched."""
        when = when or _now()
        n = 0
        with self._connect() as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            for h in records.get("hosts", []):
                eid = self._upsert(conn, "hosts", ["name"], [h["name"]],
                                   {"resolvable": _as_int(h.get("resolvable")),
                                    "status_code": h.get("status_code")}, when)
                self._observe(conn, "host", eid, tool, when)
                n += 1
            for ip in records.get("ips", []):
                eid = self._upsert(conn, "ips", ["address"], [ip["address"]],
                                   {"version": ip.get("version"),
                                    "os_name": ip.get("os_name"),
                                    "os_accuracy": ip.get("os_accuracy"),
                                    "os_cpe": ip.get("os_cpe")}, when)
                self._observe(conn, "ip", eid, tool, when)
                n += 1
            for r in records.get("dns", []):
                hid = self._upsert(conn, "hosts", ["name"], [r["host"]], {}, when)
                self._observe(conn, "host", hid, tool, when)
                if r["type"] in ("A", "AAAA"):
                    # An address answer: upsert the ip and link host -> ip,
                    # instead of duplicating the ip string in dns_records.
                    ver = 4 if r["type"] == "A" else 6
                    ipid = self._upsert(conn, "ips", ["address"], [r["value"]],
                                        {"version": ver}, when)
                    self._observe(conn, "ip", ipid, tool, when)
                    rid = self._upsert(conn, "resolutions",
                                       ["host_id", "ip_id"], [hid, ipid], {}, when)
                    self._observe(conn, "resolution", rid, tool, when)
                else:
                    eid = self._upsert(conn, "dns_records",
                                       ["host_id", "record_type", "value"],
                                       [hid, r["type"], r["value"]], {}, when)
                    self._observe(conn, "dns_record", eid, tool, when)
                n += 1
            for e in records.get("emails", []):
                hid = None
                if e.get("host"):
                    hid = self._upsert(conn, "hosts", ["name"], [e["host"]],
                                       {}, when)
                    self._observe(conn, "host", hid, tool, when)
                eid = self._upsert(conn, "emails", ["address"], [e["address"]],
                                   {"host_id": hid}, when)
                self._observe(conn, "email", eid, tool, when)
                n += 1
            for p in records.get("ports", []):
                # ip row already carries version/os from the ips list; here we
                # just resolve its id (extra={} leaves those columns intact).
                ipid = self._upsert(conn, "ips", ["address"], [p["ip"]], {}, when)
                pid = self._upsert(
                    conn, "ports", ["ip_id", "proto", "port"],
                    [ipid, p["proto"], p["port"]],
                    {k: p.get(k) for k in ("state", "reason", "service",
                     "product", "version", "extrainfo", "tunnel", "cpe",
                     "conf")}, when)
                self._observe(conn, "port", pid, tool, when)
                n += 1
            for sc in records.get("scripts", []):
                ipid = self._upsert(conn, "ips", ["address"], [sc["ip"]], {}, when)
                port_id = None
                if sc.get("port") is not None:
                    row = conn.execute(
                        "SELECT id FROM ports WHERE ip_id=? AND proto=? AND port=?",
                        (ipid, sc.get("proto"), sc["port"])).fetchone()
                    port_id = row[0] if row else None
                sid = self._upsert_script(conn, ipid, port_id, sc["script_id"],
                                          sc.get("output"), sc.get("data"), when)
                self._observe(conn, "script", sid, tool, when)
                n += 1
        return n

    @staticmethod
    def _upsert_script(conn, ip_id, port_id, script_id, output, data, when):
        """Upsert one NSE script row. Dedups on (ip_id, port_id-or-0, script_id)
        via the scripts_uq expression index so host scripts (port_id NULL) don't
        pile up. Output/data only overwrite when the new value is non-NULL."""
        row = conn.execute(
            """INSERT INTO scripts (ip_id, port_id, script_id, output, data,
                    first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip_id, COALESCE(port_id, 0), script_id) DO UPDATE SET
                   output = COALESCE(excluded.output, scripts.output),
                   data   = COALESCE(excluded.data, scripts.data),
                   last_seen = excluded.last_seen
               RETURNING id""",
            (ip_id, port_id, script_id, output, data, when, when)).fetchone()
        return row[0]

    @staticmethod
    def _upsert(conn, table, key_cols, key_vals, extra, when):
        """Insert a row (stamping first/last seen) or, if its unique key
        already exists, update last_seen plus the extra columns - always in a
        single statement. Returns the row id (RETURNING gives it on both the
        insert and the conflict path).

        COALESCE(excluded.col, table.col) means an extra column only overwrites
        when the caller actually provided a value; a NULL leaves the stored
        value intact, so e.g. a bare host reference never nulls out a
        status_code an earlier resolver set."""
        cols = list(key_cols) + list(extra) + ["first_seen", "last_seen"]
        vals = list(key_vals) + list(extra.values()) + [when, when]
        placeholders = ", ".join("?" * len(cols))
        updates = ["last_seen = excluded.last_seen"] + [
            f"{c} = COALESCE(excluded.{c}, {table}.{c})" for c in extra]
        row = conn.execute(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT({', '.join(key_cols)}) DO UPDATE SET "
            f"{', '.join(updates)} RETURNING id",
            vals).fetchone()
        return row[0]

    @staticmethod
    def _observe(conn, entity_type, entity_id, tool, when):
        conn.execute(
            """INSERT INTO observations
                   (entity_type, entity_id, tool, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(entity_type, entity_id, tool)
               DO UPDATE SET last_seen=excluded.last_seen""",
            (entity_type, entity_id, tool, when, when))

    # --- scope: user-authored, editable targets (see scancat.scope) ----------
    # Unlike the discovered entities above, scope is authoritative input the
    # user owns. Removing an entry soft-deletes it (enabled=0) so a pentest
    # keeps an audit trail of what was in scope when; nothing is ever purged.

    def scope_set(self, phase, kind, value, include=True, note=None,
                  start_ip=None, end_ip=None, when=None):
        """Insert a scope entry in `phase`, or re-enable/update it if it already
        exists. Returns the row id."""
        when = when or _now()
        with self._connect() as conn:
            row = conn.execute(
                """INSERT INTO scope (phase, kind, value, include, enabled, note,
                        start_ip, end_ip, added_at, updated_at)
                   VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                   ON CONFLICT(phase, kind, value, include) DO UPDATE SET
                       enabled    = 1,
                       note       = COALESCE(excluded.note, scope.note),
                       updated_at = excluded.updated_at
                   RETURNING id""",
                (phase, kind, value, 1 if include else 0, note,
                 start_ip, end_ip, when, when)).fetchone()
            return row[0]

    def scope_disable(self, phase, kind, value, include=None, when=None):
        """Soft-delete matching scope entries in `phase` (set enabled=0). With
        include left None, disables both the in-scope and exclusion variants.
        Returns the number of rows affected."""
        when = when or _now()
        sql = ("UPDATE scope SET enabled=0, updated_at=? "
               "WHERE phase=? AND kind=? AND value=? AND enabled=1")
        params = [when, phase, kind, value]
        if include is not None:
            sql += " AND include=?"
            params.append(1 if include else 0)
        with self._connect() as conn:
            return conn.execute(sql, params).rowcount

    def scope_active(self, phase=None):
        """Enabled scope entries as dict rows (grouped by phase, includes
        first). Pass a phase to filter; omit it for every phase."""
        if not self.path.exists():
            return []
        sql = "SELECT * FROM scope WHERE enabled=1"
        params = []
        if phase is not None:
            sql += " AND phase=?"
            params.append(phase)
        sql += " ORDER BY phase, include DESC, kind, value"
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, params)]

    def scope_domains(self, phase):
        """Active in-scope domain values in `phase`, for subdomain/DNS seeding."""
        if not self.path.exists():
            return []
        with self._connect() as conn:
            return [r[0] for r in conn.execute(
                "SELECT value FROM scope "
                "WHERE phase=? AND kind='domain' AND include=1 AND enabled=1 "
                "ORDER BY value", (phase,))]

    def scope_values(self, phase):
        """Every value already present in `phase`, in any state (enabled or not,
        include or exclude). Used by expand to avoid re-adding a host the user
        already curated (or deliberately removed) from that phase."""
        if not self.path.exists():
            return set()
        with self._connect() as conn:
            return {r[0] for r in conn.execute(
                "SELECT value FROM scope WHERE phase=?", (phase,))}

    def discovered_hosts(self):
        """All hosts discovered by recon as (name, resolvable) rows sorted by
        name. resolvable is 1 (resolved NOERROR), 0 (did not resolve), or None
        (never checked); only 1 is worth scanning by default."""
        if not self.path.exists():
            return []
        with self._connect() as conn:
            return [(r[0], r[1]) for r in conn.execute(
                "SELECT name, resolvable FROM hosts ORDER BY name")]

    def scope_reconcile(self, phase, desired, when=None):
        """Reconcile the active scope in `phase` to `desired` (an iterable of
        (kind, value, include, start_ip, end_ip, note)): each desired entry is
        inserted or re-enabled with its note (the edit is authoritative for
        notes), and active entries absent from `desired` are soft-deleted.
        Returns (added, removed) counts."""
        when = when or _now()
        desired = list(desired)
        want = {(k, v, 1 if inc else 0) for k, v, inc, *_ in desired}
        have = {(r["kind"], r["value"], r["include"])
                for r in self.scope_active(phase)}
        add, remove = want - have, have - want
        with self._connect() as conn:
            for k, v, inc, start_ip, end_ip, note in desired:
                conn.execute(
                    """INSERT INTO scope (phase, kind, value, include, enabled,
                            note, start_ip, end_ip, added_at, updated_at)
                       VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                       ON CONFLICT(phase, kind, value, include) DO UPDATE SET
                           enabled=1, note=excluded.note,
                           updated_at=excluded.updated_at""",
                    (phase, k, v, 1 if inc else 0, note,
                     start_ip, end_ip, when, when))
            for k, v, inc in remove:
                conn.execute(
                    "UPDATE scope SET enabled=0, updated_at=? "
                    "WHERE phase=? AND kind=? AND value=? AND include=?",
                    (when, phase, k, v, inc))
        return (len(add), len(remove))
