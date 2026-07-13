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
      "emails": [{"address": str}],
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
                eid = self._upsert(conn, "emails", ["address"], [e["address"]],
                                   {}, when)
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
