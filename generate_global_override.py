#!/usr/bin/env python3
"""Generate a Clash Verge Rev global override from Shadowrocket rule lists."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

GROUP_PROXY = "谷歌+AI+paypal+手动"
GROUP_DIRECT = "手动直连"
REMOTE_RULES = (
    (
        "Google",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Google/Google.list",
        GROUP_PROXY,
    ),
    (
        "PayPal",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/PayPal/PayPal.list",
        GROUP_PROXY,
    ),
    (
        "AI",
        "https://raw.githubusercontent.com/iab0x00/ProxyRules/main/Rule/AI.txt",
        GROUP_PROXY,
    ),
)

SUPPORTED_RULES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
}


def split_fields(line: str) -> List[str]:
    """Split a Shadowrocket rule while preserving commas in nested expressions."""
    fields: List[str] = []
    depth = 0
    start = 0
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


def wildcard_regex(value: str) -> str:
    """Convert Shadowrocket's * and ? domain wildcard syntax to a regex."""
    pattern = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
    return f"^{pattern}$"


def convert_rule(line: str) -> Tuple[str | None, str | None]:
    """Convert one Shadowrocket rule; return (rule, unsupported_type)."""
    fields = split_fields(line)
    if len(fields) < 2:
        return None, "malformed"
    kind, value = fields[0].upper(), fields[1]
    if kind == "IP6-CIDR":
        kind = "IP-CIDR6"
    elif kind == "DOMAIN-WILDCARD":
        kind, value = "DOMAIN-REGEX", wildcard_regex(value)
    if kind not in SUPPORTED_RULES:
        return None, kind
    suffix = ",no-resolve" if len(fields) > 2 and fields[2].lower() == "no-resolve" else ""
    return f"{kind},{value}{suffix}", None


def convert_text(text: str, target: str) -> Tuple[List[str], List[str]]:
    """Convert a rule list and append its target policy to each rule."""
    converted: List[str] = []
    skipped: List[str] = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", ";")):
            continue
        rule, reason = convert_rule(line)
        if rule is None:
            skipped.append(reason or "unknown")
            continue
        fields = split_fields(rule)
        if fields[0] in {"IP-CIDR", "IP-CIDR6"}:
            fields.insert(2, target)
        else:
            fields.append(target)
        converted.append(",".join(fields))
    return converted, skipped


def read_rules(path: Path, target: str) -> Tuple[List[str], List[str]]:
    return convert_text(path.read_text(encoding="utf-8-sig"), target)


def fetch_rules(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "shadowrocket-clash-override/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8-sig")


def script_text(rules: Sequence[str]) -> str:
    rules_json = json.dumps(list(rules), ensure_ascii=False, separators=(",", ":"))
    proxy_name = json.dumps(GROUP_PROXY, ensure_ascii=False)
    direct_name = json.dumps(GROUP_DIRECT, ensure_ascii=False)
    return f'''// Generated global extension script for Clash Verge Rev.
const overrideRules = {rules_json};

function main(config) {{
  config["proxy-groups"] = config["proxy-groups"] || [];
  config.rules = config.rules || [];

  if (!config["proxy-groups"].some(group => group.name === {proxy_name})) {{
    config["proxy-groups"].push({{ name: {proxy_name}, type: "select", "include-all": true }});
  }}
  if (!config["proxy-groups"].some(group => group.name === {direct_name})) {{
    config["proxy-groups"].push({{ name: {direct_name}, type: "select", proxies: ["DIRECT"] }});
  }}

  config.rules = overrideRules.concat(config.rules);
  return config;
}}
'''


def generate(manual_proxy: Path, manual_direct: Path, output: Path, timeout: int) -> Tuple[int, int]:
    rules: List[str] = []
    skipped: List[str] = []
    for _, url, target in REMOTE_RULES:
        converted, ignored = convert_text(fetch_rules(url, timeout), target)
        rules.extend(converted)
        skipped.extend(ignored)
    for path, target in ((manual_proxy, GROUP_PROXY), (manual_direct, GROUP_DIRECT)):
        converted, ignored = read_rules(path, target)
        rules.extend(converted)
        skipped.extend(ignored)
    output.write_text(script_text(rules), encoding="utf-8")
    if skipped:
        print(f"warning: skipped {len(skipped)} unsupported or malformed rules: {', '.join(sorted(set(skipped)))}", file=sys.stderr)
    return len(rules), len(skipped)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual-proxy", type=Path, default=Path("proxy.txt"))
    parser.add_argument("--manual-direct", type=Path, default=Path("direct.txt"))
    parser.add_argument("--output", type=Path, default=Path("clash-global-override.js"))
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        missing = [str(path) for path in (args.manual_proxy, args.manual_direct) if not path.is_file()]
        if missing:
            raise FileNotFoundError(f"missing rule file: {', '.join(missing)}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        count, skipped = generate(args.manual_proxy, args.manual_direct, args.output, args.timeout)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output} ({count} rules, {skipped} skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
