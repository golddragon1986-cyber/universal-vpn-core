#!/usr/bin/env python3
"""Build a compact SQLite lookup index from MetaCubeX's public .list files."""

import gzip
import os
import sqlite3
import sys
import tempfile
from pathlib import Path


def add_directory(db, root, kind):
    count_insert = 0
    category_insert = []
    rule_insert = []
    for path in sorted(root.glob("*.list")):
        name = path.stem
        if not name or len(name) > 128:
            continue
        count = 0
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                value = line.partition("#")[0].strip().split()
                if not value:
                    continue
                rule = value[0].strip()
                if kind == "geosite":
                    mode = "suffix" if rule.startswith(("+.", "*.")) else "exact"
                    domain = rule[2:] if mode == "suffix" else rule
                    domain = domain.rstrip(".").lower()
                    if not domain or "/" in domain or ":" in domain:
                        continue
                    rule_insert.append((name, domain, mode))
                else:
                    # Keep the category present without building an IP-address index.
                    count += 1
                    continue
                count += 1
                if len(rule_insert) >= 5000:
                    db.executemany("INSERT OR IGNORE INTO domains(category, value, mode) VALUES(?,?,?)", rule_insert)
                    rule_insert.clear()
                    count_insert += 5000
        if rule_insert:
            db.executemany("INSERT OR IGNORE INTO domains(category, value, mode) VALUES(?,?,?)", rule_insert)
            count_insert += len(rule_insert)
            rule_insert.clear()
        category_insert.append((kind, name, count))
    db.executemany("INSERT OR REPLACE INTO categories(kind, name, count) VALUES(?,?,?)", category_insert)
    return len(category_insert), count_insert


def main(source, output):
    source = Path(source)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="geodata-search-", suffix=".sqlite", dir=output.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        db = sqlite3.connect(temp)
        db.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA temp_store=MEMORY;
            CREATE TABLE categories(kind TEXT NOT NULL, name TEXT NOT NULL, count INTEGER NOT NULL,
                                    PRIMARY KEY(kind,name));
            CREATE TABLE domains(category TEXT NOT NULL, value TEXT NOT NULL, mode TEXT NOT NULL);
        """)
        site_count, domain_count = add_directory(db, source / "geosite", "geosite")
        ip_count, _ = add_directory(db, source / "geoip", "geoip")
        db.executescript("""
            CREATE INDEX categories_name ON categories(name COLLATE NOCASE);
            CREATE INDEX domains_value ON domains(value COLLATE NOCASE);
            CREATE INDEX domains_category ON domains(category);
            ANALYZE;
        """)
        db.commit()
        db.close()
        compressed = output.with_suffix(output.suffix + ".tmp")
        with temp.open("rb") as raw, compressed.open("wb") as target:
            with gzip.GzipFile(fileobj=target, mode="wb", compresslevel=6, mtime=0) as zipped:
                while chunk := raw.read(1024 * 1024):
                    zipped.write(chunk)
        compressed.replace(output)
        print(f"categories: geosite={site_count}, geoip={ip_count}; domain records={domain_count}")
        print(f"sqlite={temp.stat().st_size} bytes; gzip={output.stat().st_size} bytes")
    finally:
        temp.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: build-geodata-search-index.py UPSTREAM_GEO_DIR OUTPUT_GZ")
    main(sys.argv[1], sys.argv[2])
