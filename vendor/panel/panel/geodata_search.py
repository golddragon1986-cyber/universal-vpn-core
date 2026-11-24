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
from collections import deque
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from urllib.parse import urljoin

from geodata_domains import fields, normalize_domain, read_bytes, read_varint
from geodata_panel import entries
from vpn_subscriptions import subscription_target


SEARCH_LOCK = threading.Lock()
MAX_SOURCE = 160 * 1024 * 1024
MAX_ENTRY = 256 * 1024
RANGE_CHUNK = 10 * 1024 * 1024
RANGE_WORKERS = 2
SCAN_WORKERS = 2
SCAN_BATCH_RECORDS = 256
SCAN_BATCH_BYTES = 1024 * 1024
SCAN_MAX_PENDING = SCAN_WORKERS * 2


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


def read_url(url, reader, *, storage=None, timeout=180):
    context = ssl.create_default_context()
    deadline = time.monotonic() + timeout
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
    result = read_url_parallel(url, lambda stream: scan(stream, query))
    if result is not None:
        return result
    return read_url(url, lambda stream: scan(stream, query))


def _https_request(url, method, headers):
    """Make one pinned HTTPS request using the same public-host checks as subscriptions."""
    try:
        target, port, addresses = subscription_target(url)
    except ValueError:
        raise ValueError("Источник должен иметь публичный HTTPS-адрес.") from None
    conn = PinnedHTTPS(target.hostname, port, addresses[0][4][:2], ssl.create_default_context())
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    try:
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        return conn, response
    except (OSError, http.client.HTTPException):
        conn.close()
        raise


def _range_metadata(url):
    """Return a final URL and size only when HEAD advertises byte-range support."""
    for _ in range(6):
        conn, response = _https_request(url, "HEAD", {"User-Agent": "UvpnC/GeoDAT", "Accept-Encoding": "identity"})
        try:
            if response.status in (301, 302, 303, 307, 308) and response.getheader("Location"):
                url = urljoin(url, response.getheader("Location"))
                continue
            length = response.getheader("Content-Length", "")
            if (response.status != 200 or response.getheader("Accept-Ranges", "").lower() != "bytes"
                    or not length.isdecimal() or not 0 < int(length) <= MAX_SOURCE):
                return None
            return url, int(length)
        finally:
            conn.close()
    raise ValueError("Слишком много перенаправлений.")


def _fetch_range(url, start, end, total, deadline):
    if time.monotonic() > deadline:
        raise ValueError("Истекло время чтения GeoDAT.")
    conn, response = _https_request(url, "GET", {
        "User-Agent": "UvpnC/GeoDAT", "Accept-Encoding": "identity",
        "Range": f"bytes={start}-{end}",
    })
    try:
        content_range = response.getheader("Content-Range", "")
        expected = end - start + 1
        if response.status != 206 or content_range != f"bytes {start}-{end}/{total}":
            raise ValueError("Источник некорректно обработал диапазон GeoDAT.")
        data = response.read(expected + 1)
        if len(data) != expected:
            raise ValueError("Диапазон GeoDAT получен не полностью.")
        return data
    finally:
        conn.close()


class RangeStream:
    """Present parallel HTTP byte ranges as one sequential, bounded-memory stream."""
    def __init__(self, url, size, deadline):
        self.url = url
        self.remaining = size
        self.deadline = deadline
        self._size = size
        self._next = 0
        self._buffer = b""
        self._offset = 0
        self._futures = {}
        self._executor = ThreadPoolExecutor(max_workers=RANGE_WORKERS)
        self._schedule()

    def _schedule(self):
        while len(self._futures) < RANGE_WORKERS and self._next < self._size:
            start = self._next
            end = min(start + RANGE_CHUNK, self._size) - 1
            self._futures[start] = self._executor.submit(
                _fetch_range, self.url, start, end, self._size, self.deadline)
            self._next = end + 1

    def _next_chunk(self):
        start = self._offset
        future = self._futures.pop(start, None)
        if future is None:
            return False
        timeout = max(0, self.deadline - time.monotonic())
        self._buffer = future.result(timeout=timeout)
        self._offset = start + len(self._buffer)
        self._schedule()
        return True

    def read(self, size):
        if size < 0 or time.monotonic() > self.deadline:
            raise ValueError("Достигнут предел размера или времени чтения GeoDAT.")
        if self.remaining == 0:
            return b""
        if size > self.remaining:
            raise ValueError("Достигнут предел размера или времени чтения GeoDAT.")
        result = bytearray()
        while size:
            if not self._buffer:
                if not self._next_chunk():
                    break
            take = min(size, len(self._buffer))
            result.extend(self._buffer[:take])
            self._buffer = self._buffer[take:]
            size -= take
            self.remaining -= take
        return bytes(result)

    def close(self):
        self._executor.shutdown(wait=True, cancel_futures=True)


def read_url_parallel(url, reader, timeout=180):
    metadata = _range_metadata(url)
    if metadata is None:
        return None
    final_url, size = metadata
    stream = RangeStream(final_url, size, time.monotonic() + timeout)
    try:
        return reader(stream)
    finally:
        stream.close()


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


def _scan_record_batch(records, needles, network_text, file_kind):
    """Parse and match one bounded record batch outside the web worker process."""
    network = ipaddress.ip_network(network_text) if network_text else None
    example = None
    for raw in records:
        if file_kind == "ipcidr" and raw[:2] in (b"\x0a\x04", b"\x0a\x10"):
            end = raw[1] + 2
            tail = raw[end:]
            record = ({1: raw[2:end], 2: tail[1]}
                      if len(tail) == 2 and tail[0] == 16 and tail[1] < 128 else dict(fields(raw)))
        else:
            record = dict(fields(raw))
        kind, matched = record_matches(record, needles, network)
        if kind != file_kind:
            raise ValueError("В одном файле смешаны разные типы GeoDAT.")
        if example is None:
            example = matched
        if example is not None:
            break
    return example


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
                suffix = needle[pos + 1:]
                if b"." in suffix:
                    hints.add(suffix)
    categories = []
    pending = deque()
    file_kind = None
    network_text = str(network) if network is not None else None

    with ProcessPoolExecutor(max_workers=SCAN_WORKERS, mp_context=get_context("spawn")) as pool:
        def collect_one():
            future, state = pending.popleft()
            example = future.result()
            if state["example"] is None:
                state["example"] = example

        while True:
            tag, _ = read_varint(stream, allow_eof=True)
            if tag is None:
                if file_kind is None:
                    raise ValueError("В источнике нет категорий GeoDAT.")
                break
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
            state = {"name": name.lower(), "name_match": folded in name.casefold(),
                     "example": None, "count": 0}
            categories.append(state)
            if file_kind == "ipcidr" and network is None and not state["name_match"]:
                category.skip(category.remaining)
                continue
            count = [0]
            batch = []
            batch_bytes = 0
            for raw in category_records(category, hints if file_kind == "domain" else None, count=count):
                if file_kind == "ipcidr" and network is None:
                    continue
                if file_kind is None:
                    first = dict(fields(raw)).get(1)
                    file_kind = "ipcidr" if isinstance(first, bytes) else "domain"
                batch.append(raw)
                batch_bytes += len(raw)
                if len(batch) >= SCAN_BATCH_RECORDS or batch_bytes >= SCAN_BATCH_BYTES:
                    pending.append((pool.submit(_scan_record_batch, batch, needles, network_text, file_kind), state))
                    batch, batch_bytes = [], 0
                    if len(pending) >= SCAN_MAX_PENDING:
                        collect_one()
            if batch:
                pending.append((pool.submit(_scan_record_batch, batch, needles, network_text, file_kind), state))
            state["count"] = count[0]
        while pending:
            collect_one()

    result = []
    for state in categories:
        if state["name_match"] or state["example"] is not None:
            result.append({"name": state["name"], "kind": file_kind,
                           "name_match": state["name_match"], "example": state["example"],
                           "count": state["count"]})
    return result


def search(query, source_id=None):
    query = query.strip()
    if not 1 <= len(query) <= 253:
        raise ValueError("Введите название категории, домен, IP или сеть.")
    sources = [(sid, item) for sid, item in entries().items() if item.get("kind") == "geodat" and (source_id is None or sid == source_id)]
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
    all_categories = name == "*"
    found = False
    while True:
        tag, _ = read_varint(stream, allow_eof=True)
        if tag is None:
            if all_categories and found:
                return
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
        if all_categories or name.casefold() == current.casefold():
            yield from category_records(category, allow_reverse=allow_reverse)
            found = True
            if not all_categories:
                return
            category.skip(category.remaining)
            continue
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
    result = read_url_parallel(source["url"], reader)
    if result is not None:
        return result
    return read_url(source["url"], reader)


def save_database(url, destination, progress=None):
    """Stream a GeoDAT copy and validate its category framing before replacing it."""
    from durable_io import sync_dir
    from storage_space import require
    destination = Path(destination)
    require(destination.parent, 65536, 'Скачивание GeoDAT')
    fd, temporary = tempfile.mkstemp(prefix=".geodat-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            def download(stream):
                class Tee:
                    def __init__(self):
                        self.pending=bytearray();self.received=0;self.reported=0;self.last_report=time.monotonic()
                    @property
                    def remaining(self):return stream.remaining
                    @property
                    def deadline(self):return stream.deadline
                    def read(self,size):
                        data=stream.read(size)
                        if data:
                            self.pending.extend(data)
                            if len(self.pending)>=64*1024:self.flush_chunk()
                        elif self.pending:self.flush_chunk()
                        return data
                    def flush_chunk(self):
                        if not self.pending:return
                        chunk=bytes(self.pending);self.pending.clear()
                        require(destination.parent,len(chunk),'Скачивание GeoDAT')
                        out.write(chunk);self.received+=len(chunk)
                        now=time.monotonic()
                        if progress is not None and (self.received-self.reported>=1024*1024 or now-self.last_report>=2):
                            progress(self.received);self.reported=self.received;self.last_report=now
                tee=Tee()
                kind=detect_database(tee)
                if tee.pending:tee.flush_chunk()
                if progress is not None:progress(tee.received)
                return kind,tee.received
            kind,size=read_url(url, download, storage=destination.parent, timeout=9900)
            out.flush();os.fsync(out.fileno())
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
