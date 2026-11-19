"""Search named GeoSite and GeoIP categories from registered HTTPS sources."""

import http.client
import io
import ipaddress
import itertools
import os
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urljoin

from geodata_domains import fields, normalize_domain, read_bytes, read_varint
from geodata_panel import entries
from vpn_subscriptions import subscription_target


SEARCH_LOCK = threading.Lock()
MAX_SOURCE = 160 * 1024 * 1024
MAX_ENTRY = 256 * 1024


class LimitedStream:
    def __init__(self, stream, size, deadline):
        self.stream = stream
        self.remaining = size
        self.deadline = deadline

    def read(self, size):
        if size > self.remaining or time.monotonic() > self.deadline:
            raise ValueError("Достигнут предел размера или времени чтения GeoDAT.")
        data = self.stream.read(size)
        self.remaining -= len(data)
        return data

    def skip(self, size):
        while size:
            chunk = read_bytes(self, min(size, 64 * 1024))
            size -= len(chunk)


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, context):
        super().__init__(host, port, timeout=12, context=context)
        self.address = address

    def connect(self):
        with socket.create_connection(self.address, self.timeout) as raw:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def read_url(url, reader, *, storage=None):
    context = ssl.create_default_context()
    deadline = time.monotonic() + 180
    for _ in range(6):
        try:
            target, port, addresses = subscription_target(url)
        except ValueError:
            raise ValueError("Источник должен иметь публичный HTTPS-адрес.") from None
        conn = PinnedHTTPS(target.hostname, port, addresses[0][4][:2], context)
        try:
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            conn.request("GET", path, headers={"User-Agent": "UvpnC/GeoDAT", "Accept-Encoding": "identity"})
            with conn.getresponse() as response:
                if response.status == 200:
                    if storage is not None:
                        from storage_space import require
                        length=response.getheader('Content-Length','')
                        if length.isdecimal() and int(length)>MAX_SOURCE:raise ValueError('База GeoDAT слишком большая.')
                        require(storage,int(length) if length.isdecimal() else 65536,'Скачивание GeoDAT')
                    with io.BufferedReader(response, 64 * 1024) as buffered:
                        return reader(LimitedStream(buffered, MAX_SOURCE, deadline))
                location = response.getheader("Location")
                if response.status not in (301, 302, 303, 307, 308) or not location:
                    raise ValueError(f"Источник вернул HTTP {response.status}.")
                url = urljoin(url, location)
        finally:
            conn.close()
    raise ValueError("Слишком много перенаправлений.")


def search_url(url, query):
    return read_url(url, lambda stream: scan(stream, query))


def record_matches(record, needles, network):
    first, second = record.get(1, 0), record.get(2)
    if isinstance(first, bytes):
        if len(first) not in (4, 16) or (second is not None and not isinstance(second, int)):
            raise ValueError("Некорректная IP-запись GeoDAT.")
        bits = len(first) * 8
        prefix = second or 0
        if not 0 <= prefix <= bits:
            raise ValueError("Некорректная маска GeoDAT.")
        if network is None or bits != network.max_prefixlen:
            return "ipcidr", None
        shift = bits - min(prefix, network.prefixlen)
        if int.from_bytes(first, "big") >> shift != int(network.network_address) >> shift:
            return "ipcidr", None
        address = ipaddress.ip_address(first)
        return "ipcidr", str(ipaddress.ip_network((address, prefix), strict=False))
    if not isinstance(second, bytes):
        raise ValueError("Некорректная доменная запись GeoDAT.")
    value = second.lower()
    match = any(needle in value for needle in needles) or (
        first == 2 and any(needle.endswith(b"." + value) for needle in needles))
    return "domain", second.decode("utf-8") if match else None


def category_records(category, hints=None, *, allow_reverse=True, count=None):
    """Walk records in blocks, filtering potential domain matches before decoding."""
    chunk_size = 64 * 1024
    data = b""
    pos = 0
    while pos < len(data) or category.remaining:
        if len(data) - pos < chunk_size and category.remaining:
            data = data[pos:] + read_bytes(category, min(chunk_size, category.remaining))
            lowered = data.lower() if hints else None
            pos = 0
        tag = data[pos]
        pos += 1
        length = 0
        for shift in (0, 7, 14):
            if pos == len(data):
                raise ValueError("Запись GeoDAT обрезана.")
            byte = data[pos]
            pos += 1
            length |= (byte & 127) << shift
            if byte < 128:
                break
        else:
            raise ValueError("Запись GeoDAT слишком велика.")
        if tag == 24 and hints is None and length in (0, 1):
            if length and not allow_reverse:
                raise ValueError("Инвертированный IP-набор нельзя преобразовать в правило.")
            continue
        if tag != 18:
            raise ValueError("Неверная структура записей GeoDAT.")
        end = pos + length
        if not 0 < length <= MAX_ENTRY or end > len(data) + category.remaining:
            raise ValueError("Неверная длина записи GeoDAT.")
        if end > len(data):
            data = data[pos:] + read_bytes(category, end - len(data))
            lowered = data.lower() if hints else None
            pos, end = 0, length
        if count is not None:
            count[0] += 1
        if hints is None or any(lowered.find(hint, pos, end) >= 0 for hint in hints):
            yield data[pos:end]
        pos = end


def scan(stream, query):
    """Return matching categories with one example from the contents of each."""
    folded = query.casefold()
    needles = {folded.encode("utf-8")}
    try:
        needles.add(normalize_domain(query).encode("ascii"))
    except UnicodeError:
        pass
    try:
        network = ipaddress.ip_network(query, strict=False)
    except ValueError:
        network = None
    # Suffix candidates let us avoid decoding records without a possible match.
    hints = set(needles)
    for needle in needles:
        for pos, char in enumerate(needle):
            if char == ord(".") and pos + 1 < len(needle):
                hints.add(needle[pos + 1:])
    result = []
    file_kind = None
    while True:
        tag, _ = read_varint(stream, allow_eof=True)
        if tag is None:
            if file_kind is None:
                raise ValueError("В источнике нет категорий GeoDAT.")
            return result
        size, _ = read_varint(stream)
        if tag != 10 or not 0 < size <= stream.remaining:
            raise ValueError("Неверный формат GeoDAT.")
        category = LimitedStream(stream, size, stream.deadline)
        # RunetFreedom and v2fly write the category name first.
        name_tag, _ = read_varint(category)
        length, _ = read_varint(category)
        if name_tag != 10 or not 0 < length <= 256:
            raise ValueError("В блоке GeoDAT отсутствует название категории.")
        name = read_bytes(category, length).decode("utf-8")
        name_match = folded in name.casefold()
        example = None
        count = [0]
        if file_kind == "ipcidr" and network is None and not name_match:
            category.skip(category.remaining)
        for raw in category_records(category, hints if file_kind == "domain" else None, count=count):
            if example is not None or (file_kind == "ipcidr" and network is None):
                continue
            if file_kind == "ipcidr" and raw[:2] in (b"\x0a\x04", b"\x0a\x10"):
                end = raw[1] + 2
                tail = raw[end:]
                record = ({1: raw[2:end], 2: tail[1]}
                          if len(tail) == 2 and tail[0] == 16 and tail[1] < 128 else dict(fields(raw)))
            else:
                record = dict(fields(raw))
            kind, example = record_matches(record, needles, network)
            if file_kind is None:
                file_kind = kind
            elif file_kind != kind:
                raise ValueError("В одном файле смешаны разные типы GeoDAT.")
        if name_match or example is not None:
            result.append({"name": name.lower(), "kind": file_kind, "name_match": name_match,
                           "example": example, "count": count[0]})


def search(query):
    query = query.strip()
    if not 1 <= len(query) <= 253:
        raise ValueError("Введите название категории, домен, IP или сеть.")
    sources = [(sid, item) for sid, item in entries().items() if item.get("kind") == "geodat"]
    if not sources:
        raise ValueError("Сначала добавьте источник GeoDAT во вкладке GeoDAT.")
    if not SEARCH_LOCK.acquire(blocking=False):
        raise ValueError("Поиск по GeoDAT уже выполняется.")
    results, errors, scanned = [], [], {}
    try:
        for sid, source in sources:
            try:
                key = ("file", source["file"]) if source.get("file") else ("url", source["url"])
                if key not in scanned:
                    scanned[key] = read_source(source, lambda stream: scan(stream, query))
                matches = scanned[key]
            except (OSError, http.client.HTTPException):
                errors.append(f'{source["name"]} — не удалось прочитать источник.')
            except ValueError as error:
                errors.append(f'{source["name"]} — {error}')
            else:
                results.extend(dict(item, source=source["name"], source_id=sid) for item in matches)
    finally:
        SEARCH_LOCK.release()
    return {"results": sorted(results, key=lambda item: (not item["name_match"], item["name"], item["source"])),
            "errors": errors}


def read_category_records(stream, name, *, allow_reverse):
    while True:
        tag, _ = read_varint(stream, allow_eof=True)
        if tag is None:
            raise ValueError("Категория больше не найдена в источнике.")
        size, _ = read_varint(stream)
        if tag != 10 or not 0 < size <= stream.remaining:
            raise ValueError("Неверный формат GeoDAT.")
        category = LimitedStream(stream, size, stream.deadline)
        tag, _ = read_varint(category)
        size, _ = read_varint(category)
        if tag != 10 or not 0 < size <= 256:
            raise ValueError("В блоке GeoDAT отсутствует название категории.")
        current = read_bytes(category, size).decode("utf-8")
        if name.casefold() == current.casefold():
            yield from category_records(category, allow_reverse=allow_reverse)
            return
        category.skip(category.remaining)


def decode_rule(raw):
    rule = dict(fields(raw))
    value, argument = rule.get(1, 0), rule.get(2)
    if isinstance(value, bytes) and len(value) in (4, 16) and isinstance(rule.get(2, 0), int):
        network = ipaddress.ip_network((ipaddress.ip_address(value), argument or 0), strict=False)
        return ("networks" if network.version == 4 else "ipv6"), str(network)
    if isinstance(value, int) and 0 <= value <= 3 and isinstance(argument, bytes):
        key = ("keyword_domains", "regex_domains", "domains", "exact_domains")[value]
        return key, argument.decode("utf-8")
    raise ValueError("Неверное правило GeoDAT.")


def load_category(sid, name, *, offset=0, limit=100, preview=False):
    source = entries().get(sid)
    if not source or source.get("kind") != "geodat":
        raise ValueError("Источник GeoDAT больше не найден.")
    if not 1 <= len(name) <= 256 or offset < 0:
        raise ValueError("Некорректная категория GeoDAT.")
    def collect(stream):
        records = read_category_records(stream, name, allow_reverse=preview)
        return [decode_rule(raw) for raw in itertools.islice(records, offset, offset + limit + 1)]
    if not SEARCH_LOCK.acquire(blocking=False):
        raise ValueError("Дождитесь завершения текущего запроса GeoDAT.")
    try:
        return read_source(source, collect)
    except (OSError, http.client.HTTPException):
        raise ValueError("Не удалось прочитать источник GeoDAT.") from None
    finally:
        SEARCH_LOCK.release()


def preview_category(sid, name, offset):
    size = 100
    page = load_category(sid, name, offset=offset, limit=size, preview=True)
    prefixes = {"domains": "domain:", "exact_domains": "full:", "keyword_domains": "keyword:",
                "regex_domains": "regexp:"}
    return {"records": [prefixes.get(kind, "") + value for kind, value in page[:size]],
            "next": offset + size if len(page) > size else None}


def read_source(source, reader):
    from geodata_panel import ROOT
    if source.get("file"):
        with (ROOT / source["file"]).open("rb") as handle:
            return reader(LimitedStream(handle, MAX_SOURCE, time.monotonic() + 180))
    return read_url(source["url"], reader)


def save_database(url, destination):
    """Stream a GeoDAT copy and validate its category framing before replacing it."""
    from durable_io import sync_dir
    from storage_space import require
    destination = Path(destination)
    require(destination.parent,65536,'Скачивание GeoDAT')
    fd, temporary = tempfile.mkstemp(prefix=".geodat-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            def download(stream):
                while data := stream.read(64 * 1024):
                    require(destination.parent,len(data),'Скачивание GeoDAT')
                    out.write(data)
            read_url(url, download,storage=destination.parent)
            out.flush();os.fsync(out.fileno())
        with open(temporary, "rb") as handle:
            probe = LimitedStream(handle, MAX_SOURCE, time.monotonic() + 180)
            kind = detect_database(probe)
        size = os.path.getsize(temporary)
        os.replace(temporary, destination);sync_dir(destination.parent)
        return kind, size
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def detect_database(stream):
    kind = None
    while True:
        tag, _ = read_varint(stream, allow_eof=True)
        if tag is None:
            if kind is None:
                raise ValueError("В источнике нет категорий GeoDAT.")
            return kind
        size, _ = read_varint(stream)
        if tag != 10 or not 0 < size <= stream.remaining:
            raise ValueError("Неверный формат GeoDAT.")
        category = LimitedStream(stream, size, stream.deadline)
        name_tag, _ = read_varint(category)
        length, _ = read_varint(category)
        if name_tag != 10 or not 0 < length <= 256:
            raise ValueError("В блоке GeoDAT отсутствует название категории.")
        read_bytes(category, length).decode("utf-8")
        for raw in category_records(category):
            current = "ipcidr" if isinstance(dict(fields(raw)).get(1), bytes) else "domain"
            if kind is not None and current != kind:
                raise ValueError("В одном файле смешаны разные типы GeoDAT.")
            kind = current
            category.skip(category.remaining)
            break
