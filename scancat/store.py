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
      "ips":    [{"address": str, "version": int|None}],
      "dns":    [{"host": str, "type": str, "value": str}],   # A/AAAA/CNAME/...
      "emails": [{"address": str, "host": str|None}],   # host = domain it came from
    }

Any key may be omitted. A `dns` row's host is upserted as a host too, so the
hosts table always covers every name referenced by a record.
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
    id         INTEGER PRIMARY KEY,
    address    TEXT NOT NULL UNIQUE,
    version    INTEGER,           -- 4 or 6
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL,    -- A, AAAA, CNAME, MX, NS, TXT, ...
    value       TEXT NOT NULL,    -- IP, target host, or text
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(host_id, record_type, value)
);
CREATE TABLE IF NOT EXISTS emails (
    id         INTEGER PRIMARY KEY,
    address    TEXT NOT NULL UNIQUE,
    host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    entity_type TEXT NOT NULL,    -- 'host' | 'ip' | 'dns_record' | 'email'
    entity_id   INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_id, tool)
);
CREATE TABLE IF NOT EXISTS scope (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL,      -- 'domain'|'ip'|'cidr'|'range'
    value      TEXT NOT NULL,      -- canonical form the modules consume
    include    INTEGER NOT NULL DEFAULT 1,  -- 1 = in-scope, 0 = exclusion
    enabled    INTEGER NOT NULL DEFAULT 1,  -- 0 = soft-deleted (kept for audit)
    note       TEXT,
    start_ip   INTEGER,            -- IPv4 numeric bounds for containment tests;
    end_ip     INTEGER,            --   NULL for domains/asn and IPv6
    added_at   TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(kind, value, include)
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
        """Create the schema if it doesn't exist. Idempotent."""
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
                                   {"version": ip.get("version")}, when)
                self._observe(conn, "ip", eid, tool, when)
                n += 1
            for r in records.get("dns", []):
                hid = self._upsert(conn, "hosts", ["name"], [r["host"]], {}, when)
                self._observe(conn, "host", hid, tool, when)
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
        return n

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

    def scope_set(self, kind, value, include=True, note=None,
                  start_ip=None, end_ip=None, when=None):
        """Insert a scope entry, or re-enable/update it if it already exists.
        Returns the row id."""
        when = when or _now()
        with self._connect() as conn:
            row = conn.execute(
                """INSERT INTO scope (kind, value, include, enabled, note,
                        start_ip, end_ip, added_at, updated_at)
                   VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                   ON CONFLICT(kind, value, include) DO UPDATE SET
                       enabled    = 1,
                       note       = COALESCE(excluded.note, scope.note),
                       updated_at = excluded.updated_at
                   RETURNING id""",
                (kind, value, 1 if include else 0, note,
                 start_ip, end_ip, when, when)).fetchone()
            return row[0]

    def scope_disable(self, kind, value, include=None, when=None):
        """Soft-delete matching scope entries (set enabled=0). With include
        left None, disables both the in-scope and exclusion variants. Returns
        the number of rows affected."""
        when = when or _now()
        sql = ("UPDATE scope SET enabled=0, updated_at=? "
               "WHERE kind=? AND value=? AND enabled=1")
        params = [when, kind, value]
        if include is not None:
            sql += " AND include=?"
            params.append(1 if include else 0)
        with self._connect() as conn:
            return conn.execute(sql, params).rowcount

    def scope_active(self):
        """Enabled scope entries as dict rows (includes first, then kind/value)."""
        if not self.path.exists():
            return []
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM scope WHERE enabled=1 "
                "ORDER BY include DESC, kind, value")]

    def scope_domains(self):
        """Active in-scope domain values, for subdomain/DNS seeding."""
        if not self.path.exists():
            return []
        with self._connect() as conn:
            return [r[0] for r in conn.execute(
                "SELECT value FROM scope "
                "WHERE kind='domain' AND include=1 AND enabled=1 "
                "ORDER BY value")]

    def scope_count(self):
        if not self.path.exists():
            return 0
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM scope").fetchone()[0]

    def scope_reconcile(self, desired, when=None):
        """Reconcile the active scope to `desired` (an iterable of
        (kind, value, include, start_ip, end_ip, note)): each desired entry is
        inserted or re-enabled with its note (the edit is authoritative for
        notes), and active entries absent from `desired` are soft-deleted.
        Returns (added, removed) counts."""
        when = when or _now()
        desired = list(desired)
        want = {(k, v, 1 if inc else 0) for k, v, inc, *_ in desired}
        have = {(r["kind"], r["value"], r["include"]) for r in self.scope_active()}
        add, remove = want - have, have - want
        with self._connect() as conn:
            for k, v, inc, start_ip, end_ip, note in desired:
                conn.execute(
                    """INSERT INTO scope (kind, value, include, enabled, note,
                            start_ip, end_ip, added_at, updated_at)
                       VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                       ON CONFLICT(kind, value, include) DO UPDATE SET
                           enabled=1, note=excluded.note,
                           updated_at=excluded.updated_at""",
                    (k, v, 1 if inc else 0, note, start_ip, end_ip, when, when))
            for k, v, inc in remove:
                conn.execute(
                    "UPDATE scope SET enabled=0, updated_at=? "
                    "WHERE kind=? AND value=? AND include=?",
                    (when, k, v, inc))
        return (len(add), len(remove))

    def migrate_domains_file(self, path, when=None):
        """One-time migration off the legacy domains.txt: if scope is empty,
        import each line into scope (auto-classified). A fully-valid file is
        deleted afterwards so scope is the only source of truth; a file with
        invalid lines is kept in place for the user to fix. Returns
        (imported, invalid) where invalid is a list of (line, error). Both are
        empty when the file is absent or scope already had entries."""
        path = Path(path)
        if not path.exists() or self.scope_count() > 0:
            return 0, []
        from .scope import parse_target   # local import: avoids an import cycle
        when = when or _now()
        imported, invalid = 0, []
        with self._connect() as conn:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                result, error = parse_target(line)
                if not result:
                    invalid.append((line, error))
                    continue
                kind, value, start_ip, end_ip = result
                conn.execute(
                    """INSERT INTO scope (kind, value, include, enabled,
                            start_ip, end_ip, added_at, updated_at)
                       VALUES (?, ?, 1, 1, ?, ?, ?, ?)
                       ON CONFLICT(kind, value, include) DO NOTHING""",
                    (kind, value, start_ip, end_ip, when, when))
                imported += 1
        if not invalid:
            path.unlink()   # fully migrated; retire the legacy file
        return imported, invalid
