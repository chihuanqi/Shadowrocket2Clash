import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import generate_global_override as generator


class GlobalOverrideTests(unittest.TestCase):
    def test_shadowrocket_wildcard_becomes_domain_regex(self):
        rule, reason = generator.convert_rule("DOMAIN-WILDCARD,*mask*.icloud.com")
        self.assertIsNone(reason)
        self.assertEqual(rule, "DOMAIN-REGEX,^.*mask.*\\.icloud\\.com$")

    def test_shadowrocket_ipv6_rule_is_normalized(self):
        self.assertEqual(generator.convert_rule("IP6-CIDR,2001:db8::/32")[0], "IP-CIDR6,2001:db8::/32")
        self.assertEqual(generator.convert_rule("DOMAIN-SET,https://example.com/domains")[1], "DOMAIN-SET")

    def test_ip_no_resolve_follows_proxy_group(self):
        rules, skipped = generator.convert_text(
            "IP-CIDR,172.110.32.0/21,no-resolve\nIP6-CIDR,2001:db8::/32,no-resolve\n",
            generator.GROUP_PROXY,
        )
        self.assertEqual(skipped, [])
        self.assertEqual(rules, [
            "IP-CIDR,172.110.32.0/21,谷歌+AI+paypal+手动,no-resolve",
            "IP-CIDR6,2001:db8::/32,谷歌+AI+paypal+手动,no-resolve",
        ])

    def test_user_agent_rules_are_reported_as_unsupported(self):
        rules, skipped = generator.convert_text("USER-AGENT,Google.Drive*\n", "proxy")
        self.assertEqual(rules, [])
        self.assertEqual(skipped, ["USER-AGENT"])

    def test_script_preserves_subscription_rules_and_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manual_proxy = root / "手动代理.txt"
            manual_direct = root / "手动直连.txt"
            output = root / "override.js"
            manual_proxy.write_text("DOMAIN-SUFFIX,example.com\n", encoding="utf-8")
            manual_direct.write_text("DOMAIN,local.example\n", encoding="utf-8")
            with patch.object(generator, "fetch_rules", return_value="DOMAIN,google.com\n"):
                count, skipped = generator.generate(manual_proxy, manual_direct, output, 1)

            text = output.read_text(encoding="utf-8")
            self.assertEqual((count, skipped), (5, 0))
            runner = text + '\nconsole.log(JSON.stringify(main({"proxy-groups":[{"name":"Original","type":"select","proxies":["DIRECT"]}],"rules":["DOMAIN,original.example,Original","MATCH,Original"]})));'
            result = subprocess.run(["node", "-e", runner], capture_output=True, text=True, check=True)
            config = json.loads(result.stdout)
            self.assertEqual([group["name"] for group in config["proxy-groups"]], [
                "Original", generator.GROUP_PROXY, generator.GROUP_DIRECT,
            ])
            self.assertEqual(config["rules"][-2:], ["DOMAIN,original.example,Original", "MATCH,Original"])
            self.assertEqual(config["rules"][0], "DOMAIN,google.com,谷歌+AI+paypal+手动")
            self.assertIn("DOMAIN-SUFFIX,example.com,谷歌+AI+paypal+手动", config["rules"])
            self.assertIn("DOMAIN,local.example,手动直连", config["rules"])


if __name__ == "__main__":
    unittest.main()
