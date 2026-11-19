#!/usr/bin/env python3
import fnmatch
import re
import sys

MAX_EXPR = 1500
MAX_PATTERNS = 30
MAX_PATTERN = 300


def parse_patterns(expression):
    if not isinstance(expression, str):
        raise ValueError("Фильтр должен быть текстом")
    if len(expression) > MAX_EXPR:
        raise ValueError("Фильтр слишком длинный (максимум 1500 символов)")
    patterns = [part.strip() for part in expression.split(";") if part.strip()]
    if len(patterns) > MAX_PATTERNS:
        raise ValueError("Допускается не более 30 правил")
    parsed = []
    for item in patterns:
        if len(item) > MAX_PATTERN:
            raise ValueError("Правило длиннее 300 символов")
        if item.lower().startswith("re:"):
            source = item[3:]
            if not source:
                raise ValueError("Пустое регулярное выражение после re:")
            try:
                compiled = re.compile(source, re.IGNORECASE)
            except re.error as exc:
                raise ValueError("Некорректное регулярное выражение: " + str(exc))
            parsed.append((item, "regex", compiled))
        else:
            if any(ch.isspace() for ch in item) or "/" in item:
                raise ValueError("Маска должна быть доменной, без пробелов и '/'")
            parsed.append((item, "glob", item.lower()))
    return parsed


def matches(domain, parsed):
    for _, kind, pattern in parsed:
        if (pattern.search(domain) if kind == "regex" else fnmatch.fnmatchcase(domain, pattern)):
            return True
    return False


def filter_file(source, output, expression):
    parsed = parse_patterns(expression)
    total = kept = removed = 0
    counts = {item: 0 for item, _, _ in parsed}
    with open(source, encoding="utf-8") as inp, open(output, "w", encoding="utf-8") as out:
        for line in inp:
            value = line.strip()
            if not value.startswith("domain:"):
                raise ValueError("Источник содержит строку не формата domain:")
            domain = value[7:].strip().lower()
            if not domain:
                raise ValueError("В источнике найден пустой домен")
            total += 1
            hit = next((item for item, kind, pattern in parsed if
                        (pattern.search(domain) if kind == "regex" else fnmatch.fnmatchcase(domain, pattern))), None)
            if hit is not None:
                removed += 1
                counts[hit] += 1
            else:
                out.write("domain:" + domain + "\n")
                kept += 1
    if total and not kept:
        raise ValueError("Фильтры исключили весь источник; исходный список сохранён")
    return total, kept, removed, counts


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: domain_filter.py INPUT OUTPUT FILTER_FILE")
    try:
        with open(sys.argv[3], encoding="utf-8") as f:
            expression = f.read().strip()
    except FileNotFoundError:
        expression = ""
    total, kept, removed, counts = filter_file(sys.argv[1], sys.argv[2], expression)
    print("Source domains: %d; kept: %d; filtered: %d" % (total, kept, removed))
    for item, count in counts.items():
        print("  %s: %d" % (item, count))
