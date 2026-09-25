#!/usr/bin/env python3
"""Generate one global Clash Verge Rev YAML from Shadowrocket lazy_group.conf."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple

SOURCE_URL = (
    "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/"
    "lazy_group.conf"
)
DEFAULT_MAP = {
    "PROXY": "Proxy",
    "AI": "台湾节点",
    "YOUTUBE": "YouTube",
    "NETFLIX": "Netflix",
    "DISNEY+": "Disney+",
    "MAX": "Max",
    "SPOTIFY": "Spotify",
    "TELEGRAM": "Telegram",
    "PAYPAL": "台湾节点",
    "TWITTER": "Twitter",
    "FACEBOOK": "Facebook",
    "AMAZON": "台湾节点",
    "TIKTOK": "TikTok",
    "苹果服务": "苹果服务",
    "谷歌服务": "台湾节点",
    "微软服务": "微软服务",
    "哔哩哔哩": "哔哩哔哩",
    "游戏平台": "游戏平台",
    "香港节点": "香港节点",
    "台湾节点": "台湾节点",
    "日本节点": "日本节点",
    "新加坡节点": "新加坡节点",
    "韩国节点": "韩国节点",
    "美国节点": "美国节点",
}
MANUAL_DIRECT_RULES = [
    "DOMAIN,api.ywcode.top,manual_direct",
    "DOMAIN,code.yunfei.best,manual_direct",
    "DOMAIN,apimux.cc,manual_direct",
    "DOMAIN,www.tokensupply.net,manual_direct",
]

# Shadowrocket's DNS settings translated to Mihomo.  redir-host keeps real
# destination addresses, while the fallback filter rejects private and
# reserved answers commonly returned by DNS interception.
DNS_CONFIG = {
    "enable": True,
    "ipv6": True,
    "enhanced-mode": "redir-host",
    # Resolve DoH endpoint hostnames through numeric DNS servers to avoid
    # recursive bootstrap lookups when TUN hijacks system DNS.
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "nameserver": [
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query",
    ],
    "proxy-server-nameserver": [
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query",
    ],
}

GROUP_RE = re.compile(r"^\s*([^#][^=]*?)\s*=\s*(.+?)\s*$")
IOS_RULE_URL_RE = re.compile(
    r"^(https://raw\.githubusercontent\.com/blackmatrix7/ios_rule_script/[^/]+/rule)/"
    r"(?:Shadowrocket|QuantumultX)/(.+)\.(?:list|txt)$",
    re.IGNORECASE,
)


def clash_provider_url(url: str) -> str:
    """Use the Mihomo-compatible YAML variant of Blackmatrix7 rule sets."""
    match = IOS_RULE_URL_RE.match(url)
    if not match:
        return url
    return f"{match.group(1)}/Clash/{match.group(2)}.yaml"


def section_lines(text: str, name: str) -> List[str]:
    current = None
    result: List[str] = []
    for raw in text.splitlines():
        heading = re.match(r"^\s*\[([^]]+)\]\s*$", raw)
        if heading:
            current = heading.group(1)
            continue
        if current == name:
            result.append(raw)
    return result


def parse_groups(text: str) -> Dict[str, str]:
    groups: Dict[str, str] = {}
    for line in section_lines(text, "Proxy Group"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = GROUP_RE.match(line)
        if not match:
            continue
        name, rhs = match.groups()
        if "policy-regex-filter=" in rhs:
            regex = rhs.split("policy-regex-filter=", 1)[1].split(",", 1)[0]
            if name.strip() == "日本节点":
                regex = re.sub(r"\|日$", "", regex)
            groups[name.strip()] = regex
    return groups


def split_rule_fields(line: str) -> List[str]:
    """Split commas outside nested parentheses used by AND/OR/NOT rules."""
    fields: List[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(line):
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            fields.append(line[start:index].strip())
            start = index + 1
    fields.append(line[start:].strip())
    return fields


def parse_rules(text: str) -> Tuple[List[str], Dict[str, str]]:
    rules: List[str] = []
    providers: Dict[str, str] = {}
    provider_count: Dict[str, int] = {}
    for line in section_lines(text, "Rule"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = split_rule_fields(line)
        if not fields:
            continue
        kind = fields[0]
        if kind == "FINAL":
            if len(fields) < 2:
                continue
            target = fields[1] or "PROXY"
            rules.append(f"MATCH,{target}")
            continue
        if len(fields) < 3:
            continue
        value, target = fields[1], fields[2]
        if kind == "RULE-SET" and value.startswith(("http://", "https://")):
            provider_url = clash_provider_url(value)
            filename = re.sub(r"\.(?:list|txt|yaml)$", "", provider_url.rsplit("/", 1)[-1], flags=re.IGNORECASE)
            base = re.sub(r"[^A-Za-z0-9]+", "-", filename).strip("-").lower() or "ruleset"
            provider_count[base] = provider_count.get(base, 0) + 1
            name = base if provider_count[base] == 1 else f"{base}-{provider_count[base]}"
            providers[name] = provider_url
            rules.append(f"RULE-SET,{name},{target}")
            continue
        if kind == "GEOIP":
            rules.append(f"GEOIP,{value},{target}")
        else:
            rules.append(line.replace("FINAL,", "MATCH,", 1))
    return rules, providers


def load_map(path: Path) -> Dict[str, str]:
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_MAP, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return dict(DEFAULT_MAP)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise ValueError(f"{path} must contain a JSON object of rule target mappings")
    merged = dict(DEFAULT_MAP)
    merged.update(data)
    return merged


def map_rule_targets(rules: List[str], target_map: Dict[str, str]) -> List[str]:
    mapped_rules: List[str] = []
    for rule in rules:
        fields = split_rule_fields(rule)
        if fields[0] in {"MATCH", "FINAL"}:
            target_index = 1
        elif fields[0] in {"AND", "OR", "NOT"}:
            target_index = len(fields) - 1
        else:
            target_index = 2
        if len(fields) > target_index:
            fields[target_index] = target_map.get(fields[target_index], fields[target_index])
        mapped_rules.append(",".join(fields))
    return mapped_rules


def make_proxy_groups(target_map: Dict[str, str], source_groups: Dict[str, str]) -> List[dict]:
    region_source_names = ["香港节点", "台湾节点", "日本节点", "新加坡节点", "韩国节点", "美国节点"]
    region_filters = {target_map[name]: source_groups.get(name, ".*") for name in region_source_names}
    service_specs = [
        ("AI", ["PROXY", *region_source_names]),
        ("YOUTUBE", ["PROXY", *region_source_names]),
        ("NETFLIX", ["PROXY", *region_source_names]),
        ("DISNEY+", ["PROXY", *region_source_names]),
        ("MAX", ["PROXY", *region_source_names]),
        ("TIKTOK", ["PROXY", *region_source_names]),
        ("SPOTIFY", ["PROXY", "DIRECT", *region_source_names]),
        ("TELEGRAM", ["PROXY", *region_source_names]),
        ("TWITTER", ["PROXY", *region_source_names]),
        ("FACEBOOK", ["PROXY", *region_source_names]),
        ("PAYPAL", ["DIRECT", "PROXY", *region_source_names]),
        ("AMAZON", ["DIRECT", "PROXY", *region_source_names]),
        ("苹果服务", ["DIRECT", "PROXY", *region_source_names]),
        ("谷歌服务", ["PROXY", *region_source_names]),
        ("微软服务", ["PROXY", "DIRECT", *region_source_names]),
        ("哔哩哔哩", ["DIRECT", "PROXY", "香港节点", "台湾节点"]),
        ("游戏平台", ["DIRECT", "PROXY", *region_source_names]),
    ]

    groups: List[dict] = [{
        "name": target_map["PROXY"],
        "type": "select",
        "include-all": True,
        "proxies": ["Auto"],
    }]
    groups.extend([
        {
            "name": "manual_proxy",
            "type": "select",
            "include-all": True,
            "proxies": ["Auto"],
        },
        {
            "name": "manual_direct",
            "type": "select",
            "proxies": ["DIRECT"],
        },
    ])
    for name in region_source_names:
        region_group = {
            "name": target_map[name],
            "type": "fallback" if name in {"台湾节点", "日本节点"} else "url-test",
            "include-all": True,
            "filter": region_filters[target_map[name]],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 600,
        }
        groups.append(region_group)
    groups.append({
        "name": "Auto",
        "type": "url-test",
        "proxies": [target_map["香港节点"], target_map["台湾节点"], target_map["日本节点"]],
        "url": "http://www.gstatic.com/generate_204",
        "interval": 600,
    })
    for source_name, members in service_specs:
        group_name = target_map[source_name]
        if any(group["name"] == group_name for group in groups):
            continue
        mapped_members = [target_map.get(member, member) for member in members]
        groups.append({"name": group_name, "type": "select", "proxies": mapped_members})

    return groups


def yaml_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def yaml_lines(value: object, indent: int = 0) -> List[str]:
    pad = " " * indent
    if isinstance(value, dict):
        lines: List[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.extend(yaml_lines(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {yaml_value(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                first = True
                for key, subitem in item.items():
                    prefix = f"{pad}- {key}:" if first else f"{pad}  {key}:"
                    first = False
                    if isinstance(subitem, (dict, list)):
                        lines.append(prefix)
                        lines.extend(yaml_lines(subitem, indent + 4))
                    else:
                        lines.append(f"{prefix} {yaml_value(subitem)}")
            elif isinstance(item, list):
                lines.append(f"{pad}-")
                lines.extend(yaml_lines(item, indent + 2))
            else:
                lines.append(f"{pad}- {yaml_value(item)}")
        return lines
    return [f"{pad}{yaml_value(value)}"]


def build_unified_yaml(rules: List[str], providers: Dict[str, str], target_map: Dict[str, str], source_groups: Dict[str, str]) -> str:
    config = {
        "dns": DNS_CONFIG,
        "rule-providers": {
            name: {
                "type": "http", "behavior": "classical",
                "format": "yaml" if url.lower().endswith(".yaml") else "text",
                "url": url, "path": f"./ruleset/{name}.yaml", "interval": 86400,
            }
            for name, url in providers.items()
        },
        "proxy-groups": make_proxy_groups(target_map, source_groups),
        "rules": MANUAL_DIRECT_RULES + map_rule_targets(rules, target_map),
    }
    return "# Unified global YAML for Clash Verge Rev 2.5.5.\n" + "\n".join(yaml_lines(config)) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=SOURCE_URL)
    parser.add_argument("--output", type=Path, default=Path("clash-lazy-group.yaml"))
    parser.add_argument("--map", dest="map_path", type=Path, default=None, help="Mapping JSON; defaults beside --output")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    try:
        request = urllib.request.Request(args.source, headers={"User-Agent": "lazy-group-converter/1.0"})
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            text = response.read().decode("utf-8")
        rules, providers = parse_rules(text)
        groups = parse_groups(text)
        map_path = args.map_path or args.output.parent / "target-map.json"
        target_map = load_map(map_path)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(build_unified_yaml(rules, providers, target_map, groups), encoding="utf-8")
        print(f"wrote {args.output} ({len(rules)} rules, {len(providers)} providers)")
        print(f"mapping file: {map_path}")
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
