---
title: "Bounty Hunter — 折叠式多项式承诺的「假证明」伪造 (FortID CTF)"
description: FortID CTF Cryptography 题：BugLedger 的 TwinFold-PCS-v2 验证器从不检查每轮折叠多项式是否真由上一轮折出来，只校验单点取值，于是可以把 payout_authorized(271) 的证明值从 0 伪造成 1，骗出 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Cryptography ｜ 赛事：FortID CTF 2026 ｜ 关键词：多项式承诺、FRI 风格折叠、可靠性（soundness）缺陷、ECDSA 式否、证明伪造
>
> Flag: `FortID{Bu6_B0UN7Y_H0Un73R5_Sh0Uld_B3_4B13_70_5p07_Un50uNd_PR00fZz}`（我在团队实例上联网跑通并拿到真实 flag，下面展示构造与提交脚本）

## 题目背景

Bounty Hunter 没有附件，是个纯远程 HTTPS 服务「BugLedger」（漏洞赏金后台）。页面有 `/reports`（我名下 6 个报告）、`/transparency`（一个承诺归档包 + 8 个 shard）、`/playground`（验证器 + 样例证明）、`/vault`（付款）。目标：在 `/vault` 提交一份「有效回执」，证明某个我拥有的报告 `payout_authorized(report_id) = 1`，即可释放 flag。`/vault` 页面自曝验证器源码 `/api/replay/verifier.py`。

承诺方案叫 `TwinFold-PCS-v2`：把一个长度 8192（=2¹³）的向量（公开，8 个 shard 拼起来）用 sha256 承诺成 `commitment`，再用 13 轮「折叠」证明某个格点（由 `report_id` 的 11 bit + 列号 2 bit 组成）上的值。

## 分析

读 `verifier.py` 的 `verify(proof, manifest, vector)`，注意 **`vector` 是公开的**（我能从 shard 下载全部 8192 个值），它就是第 0 轮的多项式。每轮 `i`：

1. 校验 `commit(coeffs)` 等于「上一轮 `fold_commitments` 或 manifest 承诺」；
2. 从**当前 coeffs** 算 `a = f(x_i)`、`b = f(−x_i)`，要求等于证明给的 `rounds[i].a/b`；
3. 校验 `commit(next_coeffs) == fold_commitments[i]`；
4. 要求 `fold_value(a, b, bit_i, x_i) == 下一轮的 a`（最后一轮则 `== claimed`）；
5. `coeffs = next_coeffs` 进入下一轮。

其中 `fold_value(a,b,bit,x)`：`bit=0` 返回 `(a+b)/2`，`bit=1` 返回 `(a−b)/(2x)`（标准 FRI 偶/奇折叠）。`x_i = ρ^(2^i)`，`ρ` 由 `(snapshot, commitment, report_id, field, claimed)` 哈希确定。

先拿公开向量算真值：`payout_authorized(271)` 的格点值**确实是 0**（我需要它变成 1）。诚实情况下最后一轮会强制 `claimed == 真值 == 0`，所以诚实证明无法声称 1。

## 关键漏洞 / 关键点

**验证器从不检查 `next_coeffs` 真的是 `coeffs` 的折叠结果，只检查它在单点 `x_{i+1}` 的取值与折叠值一致。** 而除第 0 轮（= 公开向量，被 manifest 承诺钉死）外，**每一轮的多项式都由证明者自由提供**（sha256 承诺只保证绑定，不保证它是上一轮折出来的）。

这就打开了口子：

- 第 0 轮是固定的，算出 `a0 = f(ρ)`、`b0 = f(−ρ)`、`f1 = fold_value(a0,b0,bit0,ρ)`，它被迫等于第 1 轮的 `a`。
- 从第 1 轮起，我用**一次多项式** `P_i = [c0, c1]`。它需要满足 `P_i(x_i) = a_i`（被上一轮强制），但 `P_i(−x_i) = b_i` **完全自由**（两个未知数 `c0,c1` 解两个约束）。于是我能把每一轮的 `b` 设成任意值，从而把折叠结果 `fold_value(a_i, b_i, bit_i, x_i)` 操纵成**我想要的 `claimed = 1`** 并一直保持到最后一轮。
- 最后用常数多项式 `P_n = [1]` 收尾，令 `eval(P_n, x_n) = 1 = claimed` 通过末尾校验。

每轮的 `b_i` 解法（想让折叠值变成目标 `t`）：`bit=0` 时 `b = 2t − a`；`bit=1` 时 `b = a − 2·x·t`。全程在素域 `F_P` 下做。

## 利用步骤（我实际跑过的构造 + 提交）

1. 登录团队 token 取 Bearer，`PUT /api/v2/integrations/challs/bounty-hunter/instance` 开实例（返回 `https` 端点，443，本机可达）。
2. 抓 manifest、`reports.json`（得知策略：`field=payout_authorized`、`required_claimed_value="1"`、`owned_report_ids=[271,604,918,1247,1569,1842]`），下载 8 个 shard 拼出 8192 维向量。
3. 按上面思路构造证明，并用**和服务端完全一致的 `verify` 逻辑**在本地先验一遍。

```python
P = 35182531786822156541290684230036086178800502148536840364113258180206318266211
F = lambda x: int(x) % P
inv = lambda x: pow(F(x), P-2, P)
# ... h_int / challenge / ladder / eval_poly / commit / fold_value 与 verifier.py 完全一致 ...

report_id, field, claimed = 271, "payout_authorized", F(1)
bits = bits_le(report_id, 11) + bits_le(columns[field], 2)   # n = 13
rho = challenge(snapshot, commitment, report_id, field, claimed)
xs  = ladder(rho, len(bits))

P0 = vector                                        # 第 0 轮 = 公开向量，钉死
a0, b0 = eval_poly(P0, xs[0]), eval_poly(P0, -xs[0])
f1 = fold_value(a0, b0, bits[0], xs[0])            # 被迫的第 1 轮 a

A=[a0]; B=[b0]; polys=[P0]; f=f1                   # 目标：让后续折叠值全 = claimed
for i in range(1, len(bits)):
    a_i = f
    b_i = (2*claimed - a_i) % P if bits[i]==0 else (a_i - 2*xs[i]*claimed) % P
    A.append(a_i); B.append(b_i)
    f = fold_value(a_i, b_i, bits[i], xs[i])       # == claimed
for i in range(1, len(bits)):                      # 一次多项式：同时钉死 P(x_i)=a_i, P(-x_i)=b_i
    c0 = (A[i]+B[i]) * inv(2) % P
    c1 = (A[i]-B[i]) * inv(2*xs[i]) % P
    polys.append([c0, c1])
polys.append([claimed])                            # 常数收尾
fold_commitments = [commit(polys[i+1]) for i in range(len(bits))]
rounds = [{"a":str(A[i]),"b":str(B[i]),"next_coeffs":[str(c) for c in polys[i+1]]} for i in range(len(bits))]
proof = {"scheme":scheme,"snapshot_id":snapshot,"report_id":report_id,"field":field,
         "claimed_value":"1","fold_commitments":fold_commitments,"rounds":rounds}
# 本地用 verifier.py 的 verify 复算 -> (True, "accepted")
```

4. 本地验证 `True, accepted` 后，POST 到 `/vault`（`proof` 字段，表单编码）。

```python
data = urllib.parse.urlencode({"proof": json.dumps(proof)}).encode()
body = urllib.request.urlopen(..., data=data).read().decode()
# 页面里直接回显：FortID{...}
```

返回页面里出现 flag。

## Flag

```
FortID{Bu6_B0UN7Y_H0Un73R5_Sh0Uld_B3_4B13_70_5p07_Un50uNd_PR00fZz}
```

## 小结 / 收获

- 多项式承诺/IOP 的**可靠性**不能只靠「承诺 + 单点一致」：必须把相邻轮次真正用随机点绑定起来（例如要求 `next_coeffs` 在挑战点上同时匹配 `a` 和 `b` 导出的折叠多项式，或做足够多的一致性检查）。这里只校验一个点取值，证明者对第 0 轮之后的多项式有完全自由，直接把真值 0 伪造成 1。
- 「公开向量」看似无所谓，其实只有第 0 轮被它钉死，攻击正是从「第 1 轮起我说了算」切入的。
- 工程上先在本地用**与服务端一模一样的验证器**复算证明再提交，省掉所有来回调试。
