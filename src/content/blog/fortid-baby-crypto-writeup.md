---
title: "Baby Crypto — AES-CTR 用明文当 nonce 的密钥流复用 (FortID CTF)"
description: FortID CTF Intro/Crypto 题：保险库用 AES-CTR 加密，nonce 竟取 plaintext[:8]，于是只要提交一个前 8 字节和 flag 相同的「秘密」，就能复用同一段密钥流还原整条 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Cryptography（Intro）｜ 赛事：FortID CTF 2026 ｜ 关键词：AES-CTR、nonce 复用、选择明文、密钥流异或恢复
>
> Flag: （需在题目实例上运行下方脚本获取；本机沙箱只放行 443，实例的原始 TCP 服务在 1337 端口被防火墙挡住连不上，所以这里给出完整方法 + 本地用假 FLAG 的可复现验证，真实 flag 需在能连 1337 的环境跑一遍）

## 题目背景

`chall.py` 是一个「安全保险库」交互服务：

```python
class Cipher:
    def __init__(self): self.key = get_random_bytes(16)
    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=plaintext[:8])   # ← nonce = 明文前 8 字节
        return cipher.encrypt(plaintext)
```

流程：启动时生成随机 16 字节密钥，先把 `FLAG` 存进去（`Secret #0`）；菜单允许我「1) 存任意秘密」「2) 导出全部密文（hex）」「3) 退出」。`FLAG` 以 `FortID{` 开头、`}` 结尾。

## 分析

AES-CTR 是流密码：`密文 = 明文 XOR 密钥流`，密钥流 `KS = AES_key(nonce ‖ counter)` 只取决于 `(key, nonce)`。这里要命的是 **nonce = `plaintext[:8]`**：

- flag 的密文用的 nonce 是 `FLAG[:8] = "FortID{" + c`（`c` 是 flag 正文第一个字符，未知）。
- 我存自己的秘密时，nonce = 我的 `secret[:8]`，**我完全可控**。

只要我提交一个前 8 字节恰好等于 `FLAG[:8]` 的秘密，服务端就会用**同一段密钥流**加密它。拿我的已知明文异或我的密文就得到密钥流，再异或 flag 密文就还原 flag。

唯一未知是第 8 个字节 `c`。前 7 字节确定是 `FortID{`。于是对 `c` 爆破：对每个可打印候选 `c`，提交秘密 `"FortID{" + c + 足够长的填充`，拿回它的密文算出该 nonce 的密钥流，再去解 flag 密文——只有正确的 `c` 会解出以 `FortID{` 开头、`}` 结尾、全可打印的串。

## 关键漏洞 / 关键点

1. **nonce 从明文派生**（`plaintext[:8]`），导致两段前 8 字节相同的明文复用同一密钥流——CTR 模式最经典的致命错误。
2. flag 前 7 字节已知（`FortID{`），只剩 1 字节需要爆破，候选 ≤ 94 个。
3. 我提交的秘密会被 `.strip()`，所以填充用 `A`×256、避开首尾空白即可。

## 利用步骤（本地用假 FLAG 验证，完全可复现）

因为题目没给 `secret.py`，我本地起一个相同结构的保险库、放一个**假** flag 演示攻击正确性：

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

FLAG = b"FortID{this_is_a_fake_local_flag_for_demo}"   # 攻击方不知道
class Cipher:
    def __init__(self): self.key = get_random_bytes(16)
    def encrypt(self, pt): return AES.new(self.key, AES.MODE_CTR, nonce=pt[:8]).encrypt(pt)
class Vault:
    def __init__(self): self.c=Cipher(); self.e={}
    def insert(self,v): self.e[f"Secret #{len(self.e)}"]=self.c.encrypt(v.encode()).hex()
    def export(self): return json.dumps(self.e)

v = Vault(); v.insert(FLAG.decode())                   # Secret #0 = flag
flag_ct = bytes.fromhex(json.loads(v.export())["Secret #0"])

filler = "A"*256
for c in range(33,127):                                # 猜第 8 字节
    v.insert("FortID{" + chr(c) + filler)
entries = json.loads(v.export())
for idx, c in enumerate(range(33,127), start=1):
    ct = bytes.fromhex(entries[f"Secret #{idx}"])
    ks = bytes(a^b for a,b in zip(("FortID{"+chr(c)+filler).encode(), ct))   # 复原密钥流
    cand = bytes(a^b for a,b in zip(flag_ct, ks))
    if cand.startswith(b"FortID{") and cand.endswith(b"}") and all(32<=x<127 for x in cand):
        print("第8字节 =", chr(c)); print("RECOVERED:", cand); break
```

本机运行结果：

```
第8字节 = t
RECOVERED: b'FortID{this_is_a_fake_local_flag_for_demo}'
MATCH: True
```

攻击正确。**对真实实例**只需把上面的 `Vault` 换成一条 TLS/`nc` 连接：读 banner → 选 2 导出拿 `Secret #0`（flag 密文）→ 对每个候选 `c` 发「1」+ 秘密 `"FortID{"+c+"A"*256` → 再选 2 导出 → 用同样的异或逻辑筛出合法 flag。我已经把这段联网脚本写好（`baby_live.py`，经 443 的 SNI 入口会返回 HTTP 400，真正服务在 1337；本机沙箱只放行 443，故未能在此环境跑出真 flag）。

## Flag

```
（真实 flag 需在可访问实例 1337/tcp-ssl 的环境运行上述联网脚本获取；
  本机离线用假 FLAG 已验证攻击 100% 可复现）
```

## 小结 / 收获

- **nonce 绝不能从明文/可控数据派生。** CTR/GCM 的 nonce 一旦在同一密钥下重复，密钥流复用，异或两条密文直接泄露明文差，这里更是直接能复原整段密钥流。
- flag 的固定前缀（`FortID{`）把未知 nonce 压到只剩 1 字节，爆破成本极低。
- 工程上先在本地用假 flag 把攻击脚本跑通、再切到实例，省时且稳。
