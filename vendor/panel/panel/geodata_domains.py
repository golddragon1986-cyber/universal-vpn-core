"""Read a domain category from a GeoSite protobuf file."""

import io
from dataclasses import dataclass


MAX_CATEGORY_BYTES = 16 * 1024 * 1024


def read_varint(stream, *, allow_eof=False):
    value = 0
    encoded = bytearray()
    for shift in range(0, 64, 7):
        byte = stream.read(1)
        if not byte:
            if allow_eof and not encoded:
                return None, b""
            raise ValueError("Truncated GeoSite varint")
        encoded.extend(byte)
        value |= (byte[0] & 127) << shift
        if byte[0] < 128 and value < 1 << 64:
            return value, bytes(encoded)
    raise ValueError("Invalid GeoSite varint")


def read_bytes(stream, size):
    result = stream.read(size)
    if len(result) != size:
        raise ValueError("Truncated GeoSite field")
    return result


def fields(payload):
    stream = io.BytesIO(payload)
    while True:
        tag, _ = read_varint(stream, allow_eof=True)
        if tag is None:
            return
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("Invalid GeoSite field number")
        if wire == 0:
            value, _ = read_varint(stream)
        elif wire == 2:
            size, _ = read_varint(stream)
            if size > len(payload) - stream.tell():
                raise ValueError("Truncated GeoSite field")
            value = read_bytes(stream, size)
        elif wire in (1, 5):
            value = read_bytes(stream, 8 if wire == 1 else 4)
        else:
            raise ValueError("Unsupported GeoSite wire type")
        yield number, value


def category_payload(stream, category):
    """Return the encoded list entry and its payload from a seekable file."""
    stream.seek(0, io.SEEK_END)
    end = stream.tell()
    stream.seek(0)
    target = category.upper().encode("ascii")
    while stream.tell() < end:
        tag, encoded_tag = read_varint(stream)
        if tag != 10:
            raise ValueError("Expected a GeoSite list entry")
        size, encoded_size = read_varint(stream)
        start = stream.tell()
        if size > end - start:
            raise ValueError("Truncated GeoSite category")

        # Published GeoSite files encode the category name as the first field.
        # Skip other categories without reading their domain lists into memory.
        if size and read_varint(stream)[0] == 10:
            name_size, _ = read_varint(stream)
            if name_size <= min(256, start + size - stream.tell()):
                if read_bytes(stream, name_size).upper() == target:
                    if size > MAX_CATEGORY_BYTES:
                        raise ValueError("GeoSite category is too large")
                    stream.seek(start)
                    payload = read_bytes(stream, size)
                    return encoded_tag + encoded_size + payload, payload
        stream.seek(start + size)
    raise ValueError(f"GeoSite category {category} is missing")


def normalize_domain(domain):
    return domain.strip().rstrip(".").encode("idna").decode("ascii").lower()


@dataclass(frozen=True)
class DomainCategory:
    suffixes: frozenset[str]
    exact: frozenset[str]

    def match(self, domain):
        name = normalize_domain(domain)
        if name in self.exact:
            return name
        while name:
            if name in self.suffixes:
                return name
            _, _, name = name.partition(".")
        return None


def read_category(stream, category):
    encoded, payload = category_payload(stream, category)
    suffixes = set()
    exact = set()
    for field, entry in fields(payload):
        if field != 2:
            continue
        domain_fields = dict(fields(entry))
        kind = domain_fields.get(1, 0)
        if kind not in (2, 3):
            raise ValueError(f"Unsupported domain match type {kind} in {category}")
        domain = normalize_domain(domain_fields[2].decode("utf-8"))
        if not domain:
            raise ValueError(f"Empty domain in GeoSite category {category}")
        (suffixes if kind == 2 else exact).add(domain)
    if not (suffixes or exact):
        raise ValueError(f"GeoSite category {category} is empty")
    return encoded, DomainCategory(frozenset(suffixes), frozenset(exact))
