"""Small TTL-aware cache for the panel's DNS forwarder.

The key includes the client route and the original DNS question. Answers for
different routing policies must never be shared, even when the name matches.
"""
from collections import OrderedDict
import struct
import threading
import time

from dns_panel import read_name

MAX_ENTRIES = 512
MAX_TTL = 60
MAX_PACKET = 8192
_items = OrderedDict()
_lock = threading.Lock()


def _ttl_fields(answer):
    if len(answer) < 12 or len(answer) > MAX_PACKET:
        return None
    _, flags, questions, records, authority, additional = struct.unpack_from('!6H', answer)
    if flags & 0x0200 or flags & 15 or questions != 1 or not records:
        return None
    try:
        _, offset = read_name(answer, 12)
        offset += 4
        if offset > len(answer): return None
        fields = []
        answer_ttls = []
        for index in range(records + authority + additional):
            _, offset = read_name(answer, offset)
            if offset + 10 > len(answer): return None
            kind, _, ttl, length = struct.unpack_from('!HHIH', answer, offset)
            if offset + 10 + length > len(answer): return None
            if kind != 41:  # OPT stores flags in this field, not a record TTL.
                fields.append((offset + 4, ttl))
                if index < records: answer_ttls.append(ttl)
            offset += 10 + length
        if not answer_ttls or min(answer_ttls) <= 0: return None
        return fields, min(MAX_TTL, min(answer_ttls))
    except (ValueError, struct.error, UnicodeDecodeError):
        return None


def get(key, request):
    now = time.monotonic()
    with _lock:
        entry = _items.get(key)
        if entry is None: return None
        answer, fields, saved, expires = entry
        if now >= expires:
            del _items[key]
            return None
        _items.move_to_end(key)
    age = int(now - saved)
    result = bytearray(answer)
    result[:2] = request[:2]
    for offset, ttl in fields:
        struct.pack_into('!I', result, offset, max(0, ttl - age))
    return bytes(result)


def put(key, answer):
    parsed = _ttl_fields(answer)
    if parsed is None: return
    fields, ttl = parsed
    now = time.monotonic()
    with _lock:
        _items[key] = (answer, fields, now, now + ttl)
        _items.move_to_end(key)
        while len(_items) > MAX_ENTRIES:
            _items.popitem(last=False)


def clear():
    with _lock: _items.clear()
