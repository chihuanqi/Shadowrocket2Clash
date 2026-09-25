# Shadowrocket 规则转换

运行：

```bash
cd /Users/chihuanqi/Documents/Codex/2026-09-25/https-johnshall-github-io-shadowrocket-adblock/outputs
python3 convert_lazy_group.py
```

脚本每次运行都会下载最新的 `lazy_group.conf`，并只生成一份 `clash-lazy-group.yaml`。规则目标可在 `target-map.json` 中修改。

在 Clash Verge Rev 2.5.5 中，将 `clash-lazy-group.yaml` 导入「全局扩展覆写配置 → Merge」。它会全局覆盖原有 `proxy-groups` 和 `rules`，不需要对四个订阅逐个编辑，也不保留订阅自带策略组。

策略组通过 Mihomo 的 `include-all` 自动收集当前配置中的节点，不需要填写订阅名称。`Proxy` 和 `manual_proxy` 默认指向 `Auto`，避免规则模式默认直连；台湾、日本使用 `fallback`，香港使用 `url-test`；`Auto` 由香港、台湾、日本组成；最终规则为 `MATCH,Proxy`。AI、谷歌服务、Amazon 和 PayPal 使用台湾节点组。另有 `manual_direct`（DIRECT）组；`api.ywcode.top`、`code.yunfei.best`、`apimux.cc` 和 `www.tokensupply.net` 通过前置域名规则走 `manual_direct`。日本筛选正则已移除单独的 `日` 匹配。

规则集 URL 会转换为 `rule-providers`。对于 blackmatrix7 同时提供的规则，会自动改用 Mihomo 兼容的 `Clash` YAML 版本；例如 HBO：

```yaml
url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/HBO/HBO.yaml"
```

YAML 已加入 DNS 配置：使用 `redir-host`，通过 `doh.pub` 和 AliDNS 的 DoH 查询，并用数字 DNS 引导解析 DoH 服务器域名，避免 TUN 接管 DNS 后出现引导查询循环。当前网络无法稳定连接 Cloudflare/Google DoH，因此不配置它们作为 fallback；同时避免普通 UDP DNS 返回 `127.0.0.2` 等拦截地址。源配置中的 TUN、QUIC、URL Rewrite 和 MITM 选项不会进入 Clash YAML；节点本身也不在源文件中，节点由你的订阅提供。
