---
title: "King Admin — 从受限 XSS 到偷管理员可验证凭证 (FortID CTF)"
description: FortID CTF web 题：CSP nonce 可预测导致的存储型 XSS，配合 OpenID4VC 可验证凭证钱包拿下管理员登录
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：Stored XSS、CSP nonce 可预测、OpenID4VC、可验证凭证（Verifiable Credential）
>
> Flag: `FortID{4DM1N_15_F0RT1D_C0MPL14NT_BUT_5T1LL_U535_QR_C0D35_T0_L0G1N_e03e5bb496}`

## 题目背景

King Admin 是一道把**传统 Web 漏洞**和**去中心化身份（OpenID4VC / 可验证凭证）**缝在一起的题。站点登录不走密码，而是扫 QR 码出示一张"管理员凭证"。要拿 flag，就得以管理员身份完成一次 OpenID 可验证登录。

整条链条分两大段：

1. **先用一个受限的存储型 XSS**，在管理员机器人（bot）的会话里跑我的脚本，偷到一个只有管理员才能生成的"**凭证 offer**"（credential offer URI）。
2. **再用这个 offer 把管理员凭证装进我自己的钱包**，然后向站点的验证器出示它，完成登录拿 flag。

## 第一段：受限存储型 XSS

发布公告的接口 `/announcement` 会把内容存下来并展示给访问者（包括管理员 bot）。它做了过滤，但过滤得**不彻底**——只把 `on*=` 这类事件属性剥掉了（`onerror=`、`onclick=`……），却没有拦 `<script>` 标签本身。

问题是 `/admin` 页面上了 **CSP（内容安全策略）**，`script-src` 要求每个 `<script>` 带正确的 `nonce`，否则浏览器拒绝执行。所以光能插 `<script>` 还不够，得猜对 nonce。

**突破口：这个 nonce 不是随机的。** 它是由页面上的某段"提示脚本"内容算出来的：

```
nonce = sha256(hint_script_内容)[:6]
```

而提示脚本的内容只有 **10 种固定文案**（页面会从这 10 条里挑一条显示）。nonce 只有 6 个字符、且来源完全可枚举——这等于没有熵。

于是我不去"猜"，而是**把 10 种可能的 nonce 全算出来**，一次性注入 10 个 `<script>`，每个带一个候选 nonce：

```html
<script nonce="{nonce_1}">/* payload */</script>
<script nonce="{nonce_2}">/* payload */</script>
...
<script nonce="{nonce_10}">/* payload */</script>
```

不管这次页面用的是哪条提示、nonce 是哪个，10 个里**必有一个**命中、被 CSP 放行执行。受限 XSS 就这样被绕成了可执行 XSS。

## 偷管理员的凭证 offer

payload 在管理员 bot 的会话里执行，干三件事：

1. 调用只有管理员能用的接口 `POST /api/admin/offer`——它会生成一张**管理员可验证凭证的 offer URI**（OpenID4VCI 里用来领取凭证的二维码/链接）。
2. 把拿到的 `offer_uri` 带外传出来——直接再 `POST` 回 `/announcement`（我能读公告），把 offer 当公告内容发回给我自己。
3. 我轮询 `/announcement`，就收到了管理员的 offer URI。

到这里，XSS 的使命完成：我手里有了一张"任何人拿去领，就能领到管理员凭证"的 offer。

## 第二段：用钱包领凭证、再出示给验证器

这段是 OpenID4VC 的标准流程。一开始我想手搓 OpenID4VCI 的 proof（自己生成密钥、构造 proof JWT）去 `eis.fortid.com` 领，结果一直 `invalid_proof`——**手搓 proof 不是本题的预期解**。

正确做法是用赛方**自己托管的钱包服务**（经你授权我可以访问这些 `fortid.com` 域名）当工具，让它替我完成领取与出示：

```text
# 1) 拿钱包服务的 token（无需密钥）
POST cape.fortid.com/token

# 2) 创建一个钱包
POST ews.fortid.com/wallets

# 3) 用偷来的 offer 领管理员凭证
POST ews.fortid.com/.../issue/initiate      (带入 offer_uri)
POST ews.fortid.com/.../issue/{sid}/consent  body: {"preAuthorizedCodeFlow":{}}
# -> 管理员可验证凭证进钱包
```

领到凭证后，反过来向 **King Admin 站点的验证器**出示它完成登录：

```text
# 4) 在站点发起一次可验证登录，拿到 authorizationRequest
# 5) 把这个请求喂给钱包服务去"出示"
POST ews.fortid.com/.../verify/initiate       (带入 authorizationRequest)
POST ews.fortid.com/.../verify/{vsid}/present  body: {"selectedCredentialId": <管理员凭证 id>}

# 6) 轮询站点的登录状态
GET /api/login/status  -> 管理员登录成功 -> flag
```

## Flag

```
FortID{4DM1N_15_F0RT1D_C0MPL14NT_BUT_5T1LL_U535_QR_C0D35_T0_L0G1N_e03e5bb496}
```

flag 本身就是吐槽："管理员很合规，但还是在用 QR 码登录"——恰好点题。

## 小结 / 收获

- **"受限 XSS" 不等于"不可利用"**。过滤只删 `on*=`、放过 `<script>`，再加上一个 **可枚举的 CSP nonce**，就能把它绕成可执行 XSS。nonce 的安全性取决于熵——`sha256(10 种固定文案)[:6]` 等于没有熵，直接全枚举、一把梭十个 `<script>`。
- **CSP 的强度 = nonce 的不可预测性**。只要 nonce 的生成输入是有限且可知的集合，nonce 机制就形同虚设。
- **带外传数据的经典手法**：既然我同时能写 `/announcement` 又能读它，就让 bot 把偷到的东西写回这个我能读的地方。不需要外连服务器。
- **用预期的工具链，别死磕手搓**。OpenID4VC 的 proof/凭证流程很繁琐，手搓 proof 反复 `invalid_proof` 时，赛方托管的钱包服务（cape/ews）才是本题设计给你用的工具。认清"预期解"能省下大量时间。
- **组合题的关键在"接口"**：XSS 负责偷 offer，钱包服务负责领证+出示，两段各自都不稀奇，拼起来才通关。
