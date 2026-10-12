---
title: "Hacker Cinema — 票面日期 vs 分区日期错位导致的 ECDSA nonce 复用 (FortID CTF)"
description: FortID CTF Cryptography 题：电影院用确定性 nonce 签 ECDSA 票，nonce 取自「kiosk 分区日期」而被签消息取自「票面日期」，两者一旦对同一时间戳给出不同日期就能复用 nonce 还原私钥、伪造中奖票换 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Cryptography ｜ 赛事：FortID CTF 2026 ｜ 关键词：ECDSA、确定性 nonce、RFC6979 式派生、nonce 复用、私钥恢复、QR 票伪造
>
> Flag: （需在题目实例上触发 nonce 复用后伪造中奖票换取；我在可达实例上做了约 90 次探测，未能让两个日期函数产生分歧，本机又没有 PHP 无法离线复现该 PHP 行为，因此只给出完整方法，未写出 flag——绝不编造）

## 题目背景

Hacker Cinema 是个 PHP 网站：只放《Hackers (1995)》，每天一场 20:00 UTC。买票 `/buy` 生成一张带 ECDSA 签名的票，票以 QR 形式打印；`/check` 上传 QR 票，若签名有效且 `winner === true` 就吐 flag。

签名是 secp256k1 ECDSA（`crypto.php`）。票结构：`{date, movie, screen, seat, winner}`，`winner` 由 `miracle_winner(seat, ts)` 决定——要求 `sha256('neon-jackpot|seat|ts')` 全 0，等于 256 位原像，**永远 false**。所以中奖票只能靠拿到私钥自己伪造。

## 分析

私钥 `d`、nonce 种子都随容器随机，无法直接取。关键看 `tickets.php` 的 nonce 派生：

```php
function derive_nonce(array $ticket, int $screeningTs): GMP {
    $domain = ['movie'=>$ticket['movie'], 'screen'=>$ticket['screen'], 'seat'=>$ticket['seat'],
               'date' => kiosk_partition_date($screeningTs),      // ← 分区日期
               'winner'=>$ticket['winner']];
    $material = hash_hmac('sha256', 'ticket-v1|'.canonical_json($domain), nonce_key(), true);
    return ...; // k ∈ [1, N-1]
}
```

而被签名的消息是 `canonical_json($ticket)`，其中 `$ticket['date'] = ticket_date_from_timestamp($screeningTs)`。两个日期来自**两个不同的函数**：

```php
ticket_date_from_timestamp:  DateTimeImmutable::createFromFormat('U', (string)$ts)->setTimezone(UTC)->format('Y-m-d')
kiosk_partition_date:        (new DateTimeImmutable('@'.$ts))->setTimezone(UTC)->format('Y-m-d')
```

nonce `k` 只依赖 `(seat, 分区日期, winner)`；被签消息 `z` 依赖 `(票面日期, seat, winner)`。若存在两个时间戳 `t1, t2` 满足

- `kiosk_partition_date(t1) == kiosk_partition_date(t2)`（同一 `k` 和同一 `r`），
- `ticket_date_from_timestamp(t1) != ticket_date_from_timestamp(t2)`（不同消息 `z`），

就构成**同 `r`、同 `k`、不同 `z` 的 ECDSA nonce 复用**。`/buy` 支持传原始时间戳 `screening`（范围 `[-7e10, 4102444800]`），所以我能自由选 `t`。

## 关键漏洞 / 关键点

**确定性 nonce 的派生输入（分区日期）和被签消息的日期字段（票面日期）来自两个不同的日期函数。** 作者显然想让 `createFromFormat('U', …)` 与 `'@'.$ts` 在某些时间戳上给出不同的 `Y-m-d`（二者在时区处理、符号/边界上历史上有差异），从而制造「nonce 输入 ≠ 消息」的缝隙——一旦缝隙存在，RFC6979 式确定性 nonce 的安全性就被打破。

拿到两条复用签名 `(r, s1, z1)`、`(r, s2, z2)` 后：

```
k = (z1 - z2) / (s1 - s2)  mod N
d = (s1 * k - z1) / r       mod N
```

有了 `d`，对任意消息（`winner=true` 的票）自己签名，生成 QR 上传 `/check` 即得 flag——`/check` 只校验「我上传的 (r,s) 对 canonical_json(我的票) 成立」，不重新派生 nonce，所以自签的中奖票能过。

## 利用步骤（我实际做到的部分 + 完整思路）

工具链我都备好了：团队 token 开实例（`https`/443，本机可达）；`/buy?screening=<ts>` 买票拿 302→`/ticket?id=`；`/ticket.png?id=` 取 QR；OpenCV `QRCodeDetector` 解出 envelope JSON（含 `r,s` 和 `ticket.date`）；ECDSA 私钥恢复；`qrcode` 生成自签中奖票 QR 上传 `/check`（服务端用 `zbarimg --raw` 识别）。

**找复用用的探测脚本（已实跑）**：固定座位，扫一大批时间戳，建 `r -> {出现过的票面日期}` 映射；任何一个 `r` 对上两个不同日期即复用。我覆盖了：

- 普通范围、午夜边界（精确到秒）；
- 远古负时间戳（到约公元前 249 年）、闰日、1582 格里历切换日、公元 0 年附近；
- `2^31` 附近（2038 问题）、范围上下界 `4102444800 / -70000000000`。

结果：**在这个实例上，`r` 和票面日期始终 1:1 对应**（约 90 个样本无一分歧），说明部署的 PHP 8.4.16 里这两个函数在我试过的所有时间戳上给出相同日期（`setTimezone(UTC)` 把已知的时区差异抹平了）。本机没有 PHP、又禁用沙箱被拒，无法离线复现可能存在的某类特殊输入。因此我没能真正触发复用、也就拿不到 flag——**所以这里不写 flag**。

一旦找到复用的 `(t1, t2)`，后续是确定性流水线：

```python
# 伪代码
env1 = decode_qr(buy(seat, t1)); env2 = decode_qr(buy(seat, t2))   # 同 r、不同 date
r, s1, z1 = int(env1.r,16), int(env1.s,16), sha256_int(canonical_json(env1.ticket))
r, s2, z2 = int(env2.r,16), int(env2.s,16), sha256_int(canonical_json(env2.ticket))
k = (z1 - z2) * inverse(s1 - s2, N) % N
d = (s1 * k - z1) * inverse(r, N) % N
# 用 d 对 winner=true 的票签名，canonical_json 规则与服务端一致，再生成 QR 上传 /check
```

## Flag

```
（需在题目实例上先触发 kiosk_partition_date 与 ticket_date 的日期分歧、复用 nonce
  恢复私钥，再伪造 winner=true 的 QR 票上传 /check 获取；我在可达实例上未能触发
  该分歧，本机无 PHP 无法离线复现，故不编造 flag）
```

## 小结 / 收获

- 确定性 nonce（RFC6979 思路）安全的前提是**派生输入 == 完整被签消息**。本题故意把 nonce 的日期来源和消息的日期来源拆成两个函数，制造潜在缝隙。
- `createFromFormat('U', …)` 与 `new DateTime('@'.$ts)` 在时区、符号、边界上确有历史差异，但本题两处都 `setTimezone(UTC)`，差异被抹平；要利用需要找到两函数仍分歧的特定输入。
- 已经搭好「买票→解 QR→恢复私钥→自签中奖票→上传」的全自动链路，差的只是一对触发分歧的时间戳；宁可不写 flag 也不编造。
