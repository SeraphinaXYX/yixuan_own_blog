---
title: "EU Gift — 被 YAML 坑掉的黑名单放挪威进了门 (FortID CTF)"
description: 249 个国家全在黑名单里，唯独 NO 被 PyYAML 当成布尔 false 解析，于是用「挪威」签发的 EUDI 凭证就能绕过限制领走 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---
> 分类：Misc / Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：EUDI wallet、可验证凭证 (VC)、OpenID4VP、YAML Norway Problem、allow/deny list 逻辑漏洞
>
> Flag: 需要线上验证服务 `evs.fortid.com` + 一张「签发国=NO」的 EUDI 凭证才会吐出真 flag；本地 handout 里的 `flag.svg` 是占位假 flag（`FortID{this_is_a_fake_flag}`），真 flag 未能离线复现（见下方「Flag」一节说明）。

## 题目背景

题面是一句欧盟式的俏皮话：

> 🇪🇺 All EU citizens get free education, free healthcare, and a free flag! 🇪🇺

handout 解压后是一个 Flask 小站 `eu_gift`，核心文件：

- `app.py`——一个「全球 flag 放送」站点，宣称「任何持有官方 EUDI 钱包的人都能揭示 flag」；
- `config.yml`——站点配置，含验证服务地址、API key、可信根证书，以及一长串 `blocked_countries` 黑名单；
- `private/flag.svg`——flag 图片；
- 模板 `templates/*.html`、前端 `static/verify-flow.js`。

整个流程是一个 **EUDI（欧盟数字身份）钱包的可验证凭证**验证：用户用钱包扫码出示一张 PID 凭证，只披露一个字段 `issuing_country`（签发国）；站点拿着这个国家码去判断是否「允许」，允许就渲染 `flag.html` 把 flag 图片内联显示出来。

## 分析

先看判定逻辑。`app.py` 里的链路是：

```python
def evaluate_country_claims(claims):
    issuing_country = normalize_country_value(read_claim(claims, "issuing_country"))
    if not issuing_country:
        return None, "missing_issuing_country"
    country = issuing_country[0]
    if country in BLOCKED_COUNTRIES:          # ← 命中黑名单就拒
        return country, "blocked_country"
    return country, "allowed"                  # ← 否则放行
```

`normalize_country_value` 会把 `issuing_country` 规整成合法的 ISO 3166-1 alpha-2 码列表（必须 `[A-Z]{2}` 且在 pycountry 里存在）。所以**只要签发国是一个合法国家码，且不在 `BLOCKED_COUNTRIES` 里，就放行**。

而 `config.yml` 里的黑名单注释写得很「自信」：

```yaml
# Deny list of all countries that haven't yet released the official EUDI wallet
# as a hardening protection against hackers.
blocked_countries:
  - AD
  - AE
  ...
  - NO
  ...
  - ZW
```

我把这份黑名单和标准 ISO 3166-1 alpha-2 全集（249 个正式分配码）做了差集比对——**一个不差，249 个国家全在黑名单里**。按字面意思，没有任何一个国家能通过。那这题怎么解？

## 关键点 / 解法

关键在于「黑名单是用 YAML 写的，而程序用 `yaml.safe_load` 去读它」。这里踩中了著名的 **The Norway Problem（挪威问题）**：

YAML 1.1 的布尔类型解析规则会把一批裸词识别成布尔值，其中就包括 `no / No / NO`（→ `False`）和 `yes / on / off` 等。挪威的国家码恰好是 **`NO`**，当它以**不加引号**的形式写在列表里时，`yaml.safe_load` 不会把它当成字符串 `"NO"`，而是解析成 Python 的布尔值 `False`。

于是：

```python
BLOCKED_COUNTRIES = set(CONFIG.get("blocked_countries", []))
# 实际内容里，本该是 "NO" 的那一项变成了 False
```

集合里存的是布尔 `False`，而**不是字符串 `"NO"`**。所以当出示的凭证 `issuing_country = "NO"` 时：

```python
"NO" in BLOCKED_COUNTRIES   # → False（因为集合里是 bool False，不是 "NO"）
```

判定落到 `return country, "allowed"`——挪威被放行！这就是出题人埋的后门：黑名单看起来「把全世界都拦了」，实则漏了挪威这一个被 YAML 偷偷「变性」的条目。

## 求解步骤（贴实际命令/脚本/读到的关键内容）

**第一步：确认黑名单确实是 ISO 全集，排除「漏了某个国家」的可能。**

```python
import re
txt = open("config.yml").read()
blocked = set(re.findall(r"^\s*-\s+([A-Z]{2})\s*$", txt, re.M))   # 按文本抓
iso = set("AD AE AF ... NO ... ZW".split())   # 249 个标准码
print(sorted(iso - blocked))   # in ISO but NOT blocked
print(sorted(blocked - iso))   # 多出来的
# 输出都是 []  —— 文本层面 249 个国家一字不差全在黑名单里
```

**第二步：改用程序真正使用的 `yaml.safe_load` 去读，看解析后的集合。**

```python
import yaml
data = yaml.safe_load(open("config.yml"))
blocked = data["blocked_countries"]
weird = [(i, v, type(v).__name__) for i, v in enumerate(blocked) if not isinstance(v, str)]
print(weird)                       # [(166, False, 'bool')]  ← 第 166 项被解析成布尔 False
print("NO" in blocked)             # False  ← 字符串 "NO" 根本不在集合里
```

结果一目了然：列表里出现了一个 `False`（bool），正是本该是 `NO` 的那一项；字符串 `"NO"` 查不到。**挪威逃出了黑名单。**

**第三步：构造 / 出示签发国为 `NO` 的 EUDI 凭证。**

`config.yml` 还给出了验证相关的信任配置：

```yaml
verifier:
  base_url: https://evs.fortid.com
  credential_description:
    - credentialType: urn:eudi:pid:1
      credentialFormat: dc+sd-jwt
      disclosurePaths: [[issuing_country]]
  trust_config:
    - type: x5chain_root
      cert: |      # FortID Dev CA 根证书
        -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
```

所以真·利用步骤是：
1. 访问线上实例，`POST /flag` 触发 `create_verification_session`，拿到 OpenID4VP 的二维码/authorization_request；
2. 用一张 **PID 凭证（`urn:eudi:pid:1`，`dc+sd-jwt` 格式）** 来应答，只披露 `issuing_country = "NO"`，且该凭证能链到题目信任的 `FortID Dev CA`（`x5chain_root`）；
3. 站点轮询 `/verification-session/<id>/status`，判定 `allowed=True`，重定向到 `/flag/<id>`；
4. `flag_result` 渲染 `flag.html`，把 `FLAG_IMAGE`（服务器上的真 flag 图片）以 base64 data-URL 内联返回——读图即得 flag。

## Flag

本地 handout 的 `private/flag.svg` 只是占位图，内容明确写着是假 flag：

```
FortID{this_is_a_fake_flag}
```

真 flag 图片放在**线上实例的服务器**上，只有在上述验证通过后才会被 `build_flag_data_url(FLAG_IMAGE)` 渲染出来。离线包里拿不到真实的那张图，也没有能链到 `FortID Dev CA` 的挪威凭证来真正跑通验证，因此：

> **真 flag 未能离线复现**——漏洞点（YAML 把 `NO` 解析成布尔 `False` → 挪威绕过黑名单）已完整定位并验证，拿真 flag 需要连上 `evs.fortid.com` 并出示一张「签发国=NO」的可信 EUDI 凭证。

## 小结 / 收获

- **The Norway Problem 真的会咬人**：在 YAML 里裸写 `NO / ON / OFF / YES / Y / N` 这类词会被解析成布尔值。安全关键的黑/白名单，国家码、短代码一定要**加引号**（`"NO"`），或者在代码里对类型做校验。
- 这题的巧妙之处在于「把全世界都拉黑」制造了一种「绝无漏网」的错觉，真正的后门恰恰藏在那个被类型系统悄悄改掉的条目上——越是「看起来密不透风」的配置越值得逐项用程序真实加载一遍去核对。
- 做题方法论：差集比对（文本层）发现「全都被拦」之后，不要停，要换成程序**真正使用的解析器**再看一遍，解析语义和文本字面往往不一致。
