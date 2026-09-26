# Clash Verge Rev 全局扩展覆写

运行：

```bash
python3 generate_global_override.py
```

脚本下载 Google、PayPal 和 AI 规则，读取当前目录的 `手动代理.txt` 与 `手动直连.txt`，生成 `clash-global-override.js`。

在 Clash Verge Rev 中将该文件导入「全局扩展覆写配置 → Script」，保存后重载配置。脚本会保留订阅原有的规则和策略组，将新增规则放在原有规则之前。

生成两个策略组：`谷歌+AI+paypal+手动` 自动包含订阅节点，接收 Google、PayPal、AI 和 `手动代理.txt` 规则；`手动直连` 仅包含 `DIRECT`，接收 `手动直连.txt` 规则。

手动文件使用 Shadowrocket 规则格式，每行一条规则：

```text
DOMAIN-SUFFIX,example.com
DOMAIN,api.example.com
```

脚本会把 `DOMAIN-WILDCARD` 转换为 Mihomo 的 `DOMAIN-REGEX`，并保留 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR` 和 `IP-CIDR6`。`USER-AGENT` 等 Clash 没有对应类型的规则会跳过，并输出警告。

也可以指定输入和输出路径：

```bash
python3 generate_global_override.py \
  --manual-proxy ./手动代理.txt \
  --manual-direct ./手动直连.txt \
  --output ./clash-global-override.js
```
