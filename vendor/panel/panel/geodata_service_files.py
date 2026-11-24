"""Compile large GeoDAT categories into rule-provider files."""

import os
import platform
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

from durable_io import replace


ROOT = Path("/etc/mihomo/rules/geodata-services")
START = "  # BEGIN GEODAT SERVICE PROVIDERS\n"
END = "  # END GEODAT SERVICE PROVIDERS\n"
BLOCK = re.compile(re.escape(START) + r".*?" + re.escape(END), re.S)
REJECT_DNS_HEADERS = {
    "fake-ip-filter": "    ",
    "nameserver-policy": "    ",
}
FORMATS = {"domain": ("domain", "mrs"), "ip": ("ipcidr", "mrs"), "classical": ("classical", "text")}
RULES = {"keyword_domains": "DOMAIN-KEYWORD", "regex_domains": "DOMAIN-REGEX"}


def mrs_command(limit, *args):
    command = ["mihomo", "convert-ruleset", *args]
    if platform.machine().lower() in {"aarch64", "arm64"}:
        return command
    return ["/bin/sh", "-c", 'ulimit -d "$1" && shift && exec "$@"',
            "mihomo-mrs", str(limit), *command]


def provider_file(name):
    match = re.fullmatch(r"GEO-[0-9a-f]{32}-(domain|ip|classical)", name)
    if not match:
        raise ValueError("Недопустимое имя набора GeoDAT.")
    behavior, fmt = FORMATS[match[1]]
    return ROOT / f"{name}.{fmt}", behavior, fmt


def with_providers(config, blocks=""):
    config = BLOCK.sub("", config)
    if not blocks:
        return config
    header = "\nrule-providers:\n"
    if header not in config:
        raise ValueError("Не найден раздел провайдеров Mihomo.")
    return config.replace(header, header + START + blocks + END, 1)


def copy_providers(config, template):
    block = BLOCK.search(template)
    return with_providers(config, block[0][len(START):-len(END)] if block else "")


def with_reject_dns(config, providers=None, *, template="", policies=None):
    if policies is not None:
        match = re.search(r"(?m)^  nameserver:\n((?:    - .*\n)+)", config)
        if not match:
            raise ValueError("Не найден список DNS nameserver.")
        default_servers = [line.strip()[2:] for line in match[1].splitlines()]
        direct = re.search(r"(?m)^  direct-nameserver:\n((?:    - .*\n)+)", config)
        direct_servers = [line.strip()[2:] for line in direct[1].splitlines()] if direct else default_servers
    for field, indent in REJECT_DNS_HEADERS.items():
        marker = f"{indent}# SERVICE REJECT DNS {field}"
        block = re.compile(r"(?ms)^" + re.escape(marker + " BEGIN\n") +
                           r".*?^" + re.escape(marker + " END\n"))
        config = block.sub("", config)
        if policies is not None:
            if field == "nameserver-policy" and policies:
                lines = []
                for provider, reject in policies:
                    lines.append(indent + f"'rule-set:{provider}':\n")
                    servers = (["'rcode://name_error'"] if reject is True or reject == "REJECT" else
                               direct_servers if reject == "DIRECT" else default_servers)
                    lines.extend(indent + "  - " + server + "\n" for server in servers)
                content = marker + " BEGIN\n" + "".join(lines) + marker + " END\n"
            else:
                content = ""
        elif providers is None:
            match = block.search(template)
            content = match[0] if match else ""
        elif providers:
            entries = (
                f'- RULE-SET,{provider},real-ip' if field == "fake-ip-filter"
                else f"'rule-set:{provider}': 'rcode://name_error'"
                for provider in dict.fromkeys(providers)
            )
            content = marker + " BEGIN\n" + "".join(indent + entry + "\n" for entry in entries) + marker + " END\n"
        else:
            content = ""
        if content:
            header = f"\n  {field}:\n"
            if header not in config:
                raise ValueError(f"Не найден раздел DNS {field}.")
            config = config.replace(header, header + content, 1)
    return config


def compile_category(source_id, category, report=lambda _stage: None, *, inline_limit=0):
    from geodata_panel import entries
    from geodata_search import SEARCH_LOCK, decode_rule, read_category_records, read_source

    source = entries().get(source_id)
    if not source or source.get("kind") != "geodat":
        raise ValueError("Источник GeoDAT больше не найден.")
    if category == "*" and (source.get("behavior") != "domain" or not source.get("file")):
        raise ValueError("Источник должен содержать доменную базу GeoSite.")
    if not SEARCH_LOCK.acquire(blocking=False):
        raise ValueError("Дождитесь завершения текущего запроса GeoDAT.")
    names = []
    try:
        ROOT.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".compile-", dir=ROOT) as directory:
            stage = Path(directory)
            sizes = dict.fromkeys(FORMATS, 0)
            inline = []
            def collect(stream):
                with ((stage/"domain").open("w", encoding="utf-8") as domains,
                      (stage/"ip").open("w", encoding="utf-8") as ips,
                      (stage/"classical").open("w", encoding="utf-8") as classical):
                    for raw in read_category_records(stream, category, allow_reverse=False):
                        key, value = decode_rule(raw)
                        if category == "*" and key in ("networks", "ipv6"):
                            raise ValueError("Источник должен содержать доменную базу GeoSite.")
                        if not value or "\r" in value or "\n" in value:
                            raise ValueError("Некорректное правило в категории GeoDAT.")
                        if sum(sizes.values()) < inline_limit:
                            inline.append((key, value))
                        elif inline:
                            inline.clear()
                        if key in ("networks", "ipv6"):
                            ips.write(value + "\n")
                            sizes["ip"] += 1
                        elif key in RULES:
                            classical.write(RULES[key] + "," + value + "\n")
                            sizes["classical"] += 1
                        else:
                            domains.write(("+." if key == "domains" else "") + value + "\n")
                            sizes["domain"] += 1

            read_source(source, collect)
            total = sum(sizes.values())
            if total <= inline_limit:
                return [], total, inline
            report("Сборка файлов правил Mihomo")
            token = uuid.uuid4().hex
            for key, count in sizes.items():
                if not count:
                    continue
                name = f"GEO-{token}-{key}"
                destination, behavior, fmt = provider_file(name)
                output = stage/key
                if fmt == "mrs":
                    output = stage/(key + ".mrs")
                    result = subprocess.run(mrs_command(131072, behavior, "text", str(stage/key), str(output)),
                                            env={**os.environ, "GOGC": "35", "GOMEMLIMIT": "80MiB"},
                                            capture_output=True, timeout=180)
                    if result.returncode or not output.stat().st_size:
                        raise ValueError("Mihomo не смог собрать набор GeoDAT в .mrs.")
                replace(output, destination)
                names.append(name)
            if not names:
                raise ValueError("В категории нет поддерживаемых правил.")
            return names, total, None
    except Exception:
        remove_providers(names)
        raise
    finally:
        SEARCH_LOCK.release()


def remove_providers(names):
    from configuration_draft import defer_provider_removal
    if defer_provider_removal(names): return
    for name in names:
        path, behavior, _ = provider_file(name)
        path.unlink(missing_ok=True)
        if behavior == "domain":
            path.with_suffix(".domains").unlink(missing_ok=True)
