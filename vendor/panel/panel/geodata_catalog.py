"""Cached online MetaCubeX catalog search and prebuilt rule-set downloads."""

import gzip
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

from durable_io import replace


ROOT = Path("/etc/mihomo/rules")
INDEX = ROOT / "geodata-search.sqlite"
INDEX_URL = ("https://raw.githubusercontent.com/golddragon1986-cyber/universal-vpn-core/"
             "main/data/geodata-search.sqlite.gz")
RAW_BASE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/"
MAX_INDEX_GZIP = 64 * 1024 * 1024
MAX_INDEX_SIZE = 256 * 1024 * 1024
MAX_LIST_SIZE = 4 * 1024 * 1024
MAX_MRS_SIZE = 64 * 1024 * 1024
INDEX_TTL = 7 * 86400
SLUG_RE = re.compile(r"[A-Za-z0-9._!@-]{1,128}")
INDEX_LOCK = threading.Lock()


def _download(url, limit, *, timeout=25):
    request = urllib.request.Request(url, headers={"User-Agent": "UvpnC/GeoDAT-Catalog"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Ответ каталога превышает допустимый размер.")
    return data


def ensure_index(force=False):
    with INDEX_LOCK:
        return _ensure_index(force)


def _ensure_index(force=False):
    if INDEX.is_file() and not force and time.time() - INDEX.stat().st_mtime < INDEX_TTL:
        return INDEX
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, compressed_name = tempfile.mkstemp(prefix=".geo-index-", dir=ROOT)
    os.close(fd)
    compressed = Path(compressed_name)
    fd, expanded_name = tempfile.mkstemp(prefix=".geo-index-", suffix=".sqlite", dir=ROOT)
    os.close(fd)
    expanded = Path(expanded_name)
    try:
        compressed.write_bytes(_download(INDEX_URL, MAX_INDEX_GZIP, timeout=90))
        with compressed.open("rb") as handle:
            handle.seek(-4, os.SEEK_END)
            declared_size = int.from_bytes(handle.read(4), "little")
        if not 0 < declared_size <= MAX_INDEX_SIZE:
            raise ValueError("Некорректный размер индекса каталога.")
        required = declared_size + compressed.stat().st_size + 1024 * 1024
        if shutil.disk_usage(ROOT).free < required:
            raise ValueError("Недостаточно места для загрузки поискового индекса GeoDAT.")
        expanded_size = 0
        with gzip.open(compressed, "rb") as src, expanded.open("wb") as dst:
            while chunk := src.read(1024 * 1024):
                expanded_size += len(chunk)
                if expanded_size > MAX_INDEX_SIZE:
                    raise ValueError("Распакованный индекс каталога слишком велик.")
                dst.write(chunk)
        db = sqlite3.connect(f"file:{expanded.as_posix()}?mode=ro", uri=True)
        try:
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Индекс каталога повреждён.")
            if db.execute("SELECT 1 FROM categories LIMIT 1").fetchone() is None:
                raise ValueError("Индекс каталога пуст.")
        finally:
            db.close()
        replace(expanded, INDEX)
        os.utime(INDEX, None)
        return INDEX
    except (OSError, ValueError, urllib.error.URLError, sqlite3.Error, gzip.BadGzipFile, zlib.error) as error:
        if INDEX.is_file():
            os.utime(INDEX, None)
            return INDEX
        raise ValueError("Не удалось загрузить поисковый индекс GeoDAT: " + str(error)) from None
    finally:
        compressed.unlink(missing_ok=True)
        expanded.unlink(missing_ok=True)


def _normalize_domain(value):
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        return ""
    return value


def _read_list(kind, name):
    if kind not in ("geosite", "geoip") or not SLUG_RE.fullmatch(name):
        raise ValueError("Некорректная категория каталога.")
    return _download(RAW_BASE + kind + "/" + urllib.parse.quote(name, safe="") + ".list", MAX_LIST_SIZE)


def search(query):
    query = query.strip()
    if not 1 <= len(query) <= 253:
        raise ValueError("Введите название сайта или категории.")
    if query.startswith(("http://", "https://")):
        query = urllib.parse.urlsplit(query).hostname or ""
    domain = _normalize_domain(query)
    name = query.casefold().removeprefix("geosite:").removeprefix("geoip:")
    db = sqlite3.connect(f"file:{ensure_index().as_posix()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        results = []
        exact_categories = db.execute(
            "SELECT kind,name,count FROM categories WHERE name=? COLLATE NOCASE ORDER BY kind", (name,),
        ).fetchall()
        if exact_categories:
            rows = exact_categories
            name_match = "Точное совпадение категории"
        else:
            rows = db.execute(
                "SELECT kind,name,count FROM categories WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "ORDER BY CASE WHEN name LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 0 ELSE 1 END, name LIMIT 80",
                ("%" + name.replace("%", "\\%").replace("_", "\\_") + "%",
                 name.replace("%", "\\%").replace("_", "\\_") + "%"),
            ).fetchall()
            name_match = "Совпадение в названии категории"
        for row in rows:
            results.append(_result(row["kind"], row["name"], row["count"], name_match))
        if rows:
            selected = {row["name"].casefold() for row in rows}
            placeholders = ",".join("?" for _ in selected)
            paired = db.execute(
                f"SELECT kind,name,count FROM categories WHERE lower(name) IN ({placeholders}) ORDER BY name,kind",
                tuple(selected),
            ).fetchall()
            seen = {(r["kind"], r["name"].casefold()) for r in results}
            for row in paired:
                if (row["kind"], row["name"].casefold()) not in seen:
                    results.append(_result(row["kind"], row["name"], row["count"], "Связанная категория"))

        direct = []
        should_search_content = not exact_categories or (domain and "." in domain)
        if should_search_content and domain and "." in domain:
            suffixes = [".".join(domain.split(".")[i:]) for i in range(len(domain.split(".")))]
            placeholders = ",".join("?" for _ in suffixes)
            direct = db.execute(
                f"SELECT DISTINCT d.category,c.count FROM domains d JOIN categories c ON c.kind='geosite' AND c.name=d.category "
                f"WHERE d.value COLLATE NOCASE IN ({placeholders}) AND (d.mode='exact' AND d.value=? COLLATE NOCASE OR d.mode='suffix') "
                "ORDER BY d.category LIMIT 80", (*suffixes, domain),
            ).fetchall()
        if should_search_content and not direct:
            needle = name.replace("%", "\\%").replace("_", "\\_")
            direct = db.execute(
                "SELECT DISTINCT d.category,c.count FROM domains d JOIN categories c ON c.kind='geosite' AND c.name=d.category "
                "WHERE d.value LIKE ? ESCAPE '\\' COLLATE NOCASE ORDER BY d.category LIMIT 80", ("%" + needle + "%",),
            ).fetchall()
        for row in direct:
            results.append(_result("geosite", row["category"], row["count"], "Совпадение по домену"))
            paired = db.execute("SELECT count FROM categories WHERE kind='geoip' AND name=? COLLATE NOCASE", (row["category"],)).fetchone()
            if paired:
                results.append(_result("geoip", row["category"], paired[0], "IP-набор с тем же названием"))
        unique = {}
        for item in results:
            key = (item["kind"], item["name"].casefold())
            if key not in unique or item["match"].startswith("Точное совпадение"):
                unique[key] = item
        ordered = sorted(unique.values(), key=lambda item: (not item["match"].startswith("Точное совпадение"),
                                                            not item["match"].startswith("Совпадение в названии"),
                                                            item["name"].casefold(), item["kind"]))
        return {"results": ordered[:100], "errors": [], "index": "MetaCubeX"}
    finally:
        db.close()


def _result(kind, name, count, match):
    return {"name": name, "kind": kind, "source": "MetaCubeX", "source_id": "meta:" + kind,
            "count": count, "match": match, "example": match}


def preview(kind, name, offset=0):
    if offset < 0 or offset > 200000:
        raise ValueError("Некорректная позиция просмотра.")
    rows = []
    for line in _read_list(kind, name).decode("utf-8-sig", "replace").splitlines():
        value = line.partition("#")[0].strip()
        if value:
            rows.append(value)
    page = rows[offset:offset + 100]
    return {"records": page, "next": offset + 100 if offset + 100 < len(rows) else None}


def download_provider(kind, name, provider, report=lambda _stage: None):
    from geodata_service_files import provider_file

    if kind not in ("geosite", "geoip") or not SLUG_RE.fullmatch(name):
        raise ValueError("Некорректная категория каталога.")
    path, behavior, _fmt = provider_file(provider)
    expected = "domain" if kind == "geosite" else "ip"
    if behavior != expected:
        raise ValueError("Тип набора не соответствует категории.")
    db = sqlite3.connect(f"file:{ensure_index().as_posix()}?mode=ro", uri=True)
    try:
        row = db.execute("SELECT count FROM categories WHERE kind=? AND name=? COLLATE NOCASE",
                         (kind, name)).fetchone()
    finally:
        db.close()
    if row is None:
        raise ValueError("Категория исчезла из индекса.")
    count = int(row[0])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    report("Загрузка готового набора MRS")
    data = _download(RAW_BASE + kind + "/" + urllib.parse.quote(name, safe="") + ".mrs", MAX_MRS_SIZE, timeout=60)
    if len(data) < 4 or data[:4] != b"\x28\xb5\x2f\xfd":
        raise ValueError("Источник вернул файл не в формате MRS.")
    if shutil.disk_usage(path.parent).free < len(data) + 1024 * 1024:
        raise ValueError("Недостаточно места для загрузки набора GeoDAT.")
    fd, temporary = tempfile.mkstemp(prefix=".catalog-mrs-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return count
