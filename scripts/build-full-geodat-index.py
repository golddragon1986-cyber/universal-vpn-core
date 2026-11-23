Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.
#!/usr/bin/env python3
"""Experimental full index builder for V2Ray geosite.dat and geoip.dat."""

import gzip
import ipaddress
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path


def varint(data, pos):
    value = shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 70:
            break
    raise ValueError("invalid protobuf varint")


def fields(data):
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == 2:
            size, pos = varint(data, pos)
            value, pos = data[pos:pos + size], pos + size
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield number, wire, value


def nested(data, field_number):
    return (value for number, wire, value in fields(data)
            if number == field_number and wire == 2)


def text_field(data, field_number):
    for number, wire, value in fields(data):
        if number == field_number and wire == 2:
            return value.decode("utf-8", "replace")
    return ""


def add_geosite(db, path):
    categories = domains = 0
    batch = []
    # The complete binaries are modest enough to hold in memory, and reading them
    # whole avoids splitting protobuf messages at arbitrary I/O chunk boundaries.
    data = path.read_bytes()
    for site in nested(data, 1):
        category = text_field(site, 1).strip().lower()
        if not category:
            continue
        categories += 1
        count = 0
        for item in nested(site, 2):
            domain_type, value = 0, None
            for number, wire, field_value in fields(item):
                if number == 1 and wire == 0:
                    domain_type = field_value
                elif number == 2 and wire == 2:
                    value = field_value.decode("utf-8", "replace").strip().lower().rstrip(".")
            if not value:
                continue
            mode = {0: "keyword", 1: "regex", 2: "suffix", 3: "exact"}.get(domain_type, "other")
            batch.append((category, value, mode))
            count += 1
            domains += 1
            if len(batch) >= 10000:
                db.executemany("INSERT INTO domains(category,value,mode) VALUES(?,?,?)", batch)
                batch.clear()
        db.execute("INSERT INTO categories(kind,name,count) VALUES('geosite',?,?)", (category, count))
    if batch:
        db.executemany("INSERT INTO domains(category,value,mode) VALUES(?,?,?)", batch)
    return categories, domains


def add_geoip(db, path):
    categories = networks = 0
    batch = []
    data = path.read_bytes()
    for entry in nested(data, 1):
        category = text_field(entry, 1).strip().lower()
        if not category:
            continue
        categories += 1
        count = 0
        for cidr in nested(entry, 2):
            raw_ip, prefix = None, 0
            for number, wire, value in fields(cidr):
                if number == 1 and wire == 2:
                    raw_ip = value
                elif number == 2 and wire == 0:
                    prefix = value
            if raw_ip is None or prefix is None or len(raw_ip) not in (4, 16):
                continue
            family = 4 if len(raw_ip) == 4 else 6
            bits = len(raw_ip) * 8
            if prefix > bits:
                continue
            address = int.from_bytes(raw_ip, "big")
            mask = ((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1) if prefix else 0
            network = (address & mask).to_bytes(len(raw_ip), "big")
            batch.append((category, family, prefix, network))
            count += 1
            networks += 1
            if len(batch) >= 10000:
                db.executemany("INSERT INTO ip_networks(category,family,prefix,network) VALUES(?,?,?,?)", batch)
                batch.clear()
        db.execute("INSERT INTO categories(kind,name,count) VALUES('geoip',?,?)", (category, count))
    if batch:
        db.executemany("INSERT INTO ip_networks(category,family,prefix,network) VALUES(?,?,?,?)", batch)
    return categories, networks


def bench(db, samples=30):
    queries = {
        "domain_exact_suffix": ("SELECT DISTINCT d.category FROM domains d WHERE d.value IN (?,?,?) AND (d.mode='exact' AND d.value=? OR d.mode='suffix')", ("rr1---sn-ixh7rn76.googlevideo.com", "googlevideo.com", "com", "rr1---sn-ixh7rn76.googlevideo.com")),
        "domain_substring": ("SELECT DISTINCT category FROM domains WHERE value LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 80", ("%googlevideo.com%",)),
        "category_name": ("SELECT kind,name FROM categories WHERE name LIKE ? LIMIT 100", ("%google%",)),
    }
    runs = {}
    for name, (sql, args) in queries.items():
        timings = []
        for _ in range(samples):
            started = time.perf_counter()
            db.execute(sql, args).fetchall()
            timings.append((time.perf_counter() - started) * 1000)
        timings.sort()
        runs[name] = (timings[len(timings) // 2], timings[-1])
    address = ipaddress.ip_address("1.1.1.1")
    timings = []
    for _ in range(samples):
        started = time.perf_counter()
        for prefix in range(address.max_prefixlen + 1):
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False).network_address.packed
            db.execute("SELECT category FROM ip_networks WHERE family=? AND prefix=? AND network=?",
                       (address.version, prefix, network)).fetchall()
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    runs["geoip_lookup"] = (timings[len(timings) // 2], timings[-1])
    return runs


def main(geosite_path, geoip_path, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="full-geodata-", suffix=".sqlite", dir=output.parent)
    os.close(fd)
    temp = Path(temp_name)
    started = time.perf_counter()
    try:
        db = sqlite3.connect(temp)
        db.executescript("""
            PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA temp_store=MEMORY;
            CREATE TABLE categories(kind TEXT NOT NULL,name TEXT NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(kind,name));
            CREATE TABLE domains(category TEXT NOT NULL,value TEXT NOT NULL,mode TEXT NOT NULL);
            CREATE TABLE ip_networks(category TEXT NOT NULL,family INTEGER NOT NULL,prefix INTEGER NOT NULL,network BLOB NOT NULL);
        """)
        site_categories, domain_count = add_geosite(db, Path(geosite_path))
        ip_categories, network_count = add_geoip(db, Path(geoip_path))
        db.executescript("""
            CREATE INDEX categories_name ON categories(name COLLATE NOCASE);
            CREATE INDEX domains_value ON domains(value COLLATE NOCASE);
            CREATE INDEX domains_mode_value ON domains(mode,value COLLATE NOCASE);
            CREATE INDEX ip_lookup ON ip_networks(family,prefix,network,category);
            ANALYZE;
        """)
        db.commit()
        build_elapsed = time.perf_counter() - started
        bench_results = bench(db)
        db.close()
        sqlite_size = temp.stat().st_size
        gz_path = output.with_suffix(output.suffix + ".tmp")
        gzip_started = time.perf_counter()
        with temp.open("rb") as raw, gz_path.open("wb") as target:
            with gzip.GzipFile(fileobj=target, mode="wb", compresslevel=6, mtime=0) as zipped:
                while chunk := raw.read(1024 * 1024):
                    zipped.write(chunk)
        gz_path.replace(output)
        print(f"categories: geosite={site_categories}, geoip={ip_categories}")
        print(f"records: domain={domain_count}, geoip_network={network_count}, total={domain_count + network_count}")
        print(f"sizes: sqlite={sqlite_size} bytes ({sqlite_size/1024/1024:.2f} MiB), gzip={output.stat().st_size} bytes ({output.stat().st_size/1024/1024:.2f} MiB)")
        print(f"timing: build={build_elapsed:.2f}s, gzip={time.perf_counter()-gzip_started:.2f}s")
        for name, (median, maximum) in bench_results.items():
            print(f"search {name}: median={median:.3f}ms max={maximum:.3f}ms ({30} runs)")
    finally:
        temp.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Usage: build-full-geodat-index.py GEOSITE_DAT GEOIP_DAT OUTPUT_GZ")
    main(*sys.argv[1:])

