---
title: "DESBox — 用「全同字节密钥」击穿随机置换的 3DES 预言机 (FortID CTF)"
description: FortID CTF Cryptography 题：伪装成 DOS 模拟器的 3DES 服务在加载密钥前会随机置换字节再异或秘密 MASK，但只要提交 24 个相同字节的密钥，置换就形同虚设，跨两次调用把加密用的密钥搬到解密端即可还原 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Cryptography ｜ 赛事：FortID CTF 2026 ｜ 关键词：3DES/ECB、随机字节置换、固定点攻击、加密+解密预言机、密钥搬运
>
> Flag: （需在题目实例上运行下方交互脚本获取；`secret.py` 里的 FLAG/MASK 被打码，且实例是 1337/tcp-ssl，本机沙箱只放行 443 连不上，所以给出完整方法 + 本地随机 MASK/假 FLAG 的可复现验证）

## 题目背景

`DESBox.py` 把自己伪装成 DOS 下的 `KEYB.COM`。关键函数：

```python
def load_key(user_key):
    key = xor(permute(user_key), MASK)          # 先随机置换 24 字节，再异或秘密 MASK
    return DES3.adjust_key_parity(key)

def run_keyb():
    key_a, key_b = read_keys()                  # 读两个 24 字节 hex 密钥
    print(DES3.new(key_a, DES3.MODE_ECB).encrypt(FLAG).hex())   # 用 key_a 加密 FLAG 给我
    ct = bytes.fromhex(input("Debug ciphertext> "))
    print(DES3.new(key_b, DES3.MODE_ECB).decrypt(ct).hex())     # 用 key_b 解密我给的密文
```

即每次 `KEYB` 调用：我给两个用户密钥 `key_a/key_b`，服务端分别对它们做 `load_key`（随机置换 + 异或 MASK + 调整奇偶校验），然后**用 `key_a` 加密 flag 发给我**、**用 `key_b` 解密我任意选的密文**。`read_keys` 还有一堆限制：两个密钥不能相等、有效字节（去掉最低校验位）不能相等、不能是同一多重集、不能是「有效比特互补」。

## 分析

3DES ECB 下，如果我能让某次调用的 `key_b` 等于另一次调用的 `key_a`，就能把 flag 密文丢到解密端直接还原。但问题是：

1. `permute` 每次调用**都重新随机洗牌** 24 个字节；
2. `MASK` 是未知的固定秘密；
3. 奇偶校验位被重置（DES 本就忽略最低位）。

看似每次 `load_key` 结果都随机。**但致命点在 `permute` 作用于一个全是相同字节的输入时是恒等的**：若 `user_key` 的 24 个字节全等于 `v`，则无论怎么洗牌，`permute` 输出仍是 24 个 `v`，于是

```
load_key(v*24) = adjust_parity( (v*24) XOR MASK )  =: f(v)
```

**完全确定，和随机置换无关！** 而且 `MASK`、奇偶校验在每次调用里是同一套变换，所以 `f(v)` 跨调用稳定不变。

这样我就有了：对任意字节 `v`，一个「用 `f(v)` 加密 flag」的预言机（把 `v*24` 当 `key_a`）和一个「用 `f(w)` 解密任意密文」的预言机（把 `w*24` 当 `key_b`）。

## 关键漏洞 / 关键点

1. **随机置换对「全同字节」输入无效**（固定点），把本该随机的 `load_key` 变成确定函数 `f(v)`。
2. `f(v)` 跨两次 `KEYB` 调用完全一致（MASK/奇偶处理相同）。
3. 一次调用内 `key_a≠key_b` 的各种限制，用「全同字节但 `v≠v'`」且避开互补/同多重集即可轻松满足（全同字节时多重集就是 `{v}`，只要 `v&0xFE ≠ v'&0xFE` 且 `v' ≠ v^0xFE` 即可）。

于是攻击：第 1 次调用用 `key_a = v*24` 拿到 `C = Enc_{f(v)}(FLAG)`；第 2 次调用把 `key_b = v*24`（= 第 1 次的 `f(v)`），`Debug ciphertext` 填 `C`，解密端输出 `Dec_{f(v)}(C) = FLAG`。两次调用解耦，正好绕开「同一次里 `key_a`、`key_b` 必须不同」的限制。

## 利用步骤（本地随机 MASK + 假 FLAG 验证，可复现）

```python
import secrets
from Crypto.Cipher import DES3
RNG = secrets.SystemRandom()
MASK = secrets.token_bytes(24)                      # 模拟未知秘密
FLAG = b"FortID{desbox_fake_demo__}"; FLAG += b"\x00"*((-len(FLAG))%8)

def permute(a):
    p = list(range(len(a))); RNG.shuffle(p); return bytes(a[i] for i in p)
def load_key(uk): return DES3.adjust_key_parity(bytes(x^y for x,y in zip(permute(uk), MASK)))
def keyb(ka, kb, debug_ct=None):                    # 复刻服务端一次 KEYB（省略那几条合法性断言）
    key_a, key_b = load_key(ka), load_key(kb)
    C = DES3.new(key_a, DES3.MODE_ECB).encrypt(FLAG)
    out = DES3.new(key_b, DES3.MODE_ECB).decrypt(debug_ct) if debug_ct is not None else None
    return C, out

# 第 1 次：key_a = 0x00*24 -> 拿 C = Enc_{f(0x00)}(FLAG)
C, _ = keyb(bytes([0x00])*24, bytes([0x02])*24)
# 第 2 次：key_b = 0x00*24 = 第 1 次的 f(0x00)，解密 C
_, flag = keyb(bytes([0x04])*24, bytes([0x00])*24, debug_ct=C)
print(flag.rstrip(b"\x00"))                          # -> b'FortID{desbox_fake_demo__}'
```

本机输出 `b'FortID{desbox_fake_demo__}'`，`MATCH: True`，攻击正确。

**对真实实例**（1337/tcp-ssl）只需按协议交互：进 shell → `KEYB` → `KEY A> 00·24`、`KEY B> 02·24`（hex 即 `"00"*24`、`"02"*24`）→ 记下回显的 flag 密文 `C` → 再 `KEYB` → `KEY A> 04·24`、`KEY B> 00·24` → `Debug ciphertext> C` → 读出的 hex 即 flag（去掉可能的填充）。注意 FLAG 长度是 8 的倍数（题目有断言），ECB 分块直接对应。

## Flag

```
（真实 flag 需在可访问实例 1337/tcp-ssl 的环境运行上述交互获取；
  本机离线用随机 MASK + 假 FLAG 已验证攻击必然成功）
```

## 小结 / 收获

- **任何「随机置换/打乱」碰到全同元素输入都是恒等的**——这是把随机化防护变成固定函数的通用技巧。
- 当服务同时给「加密预言机」和「解密预言机」且密钥可被我钉成同一个确定值时，加解密直接对消。
- 一次调用内的各种「密钥必须不同」限制，用「跨调用」手法（两次 `KEYB`）轻松绕开。
- 处理不可信题目脚本：单独目录存放、我的脚本另放、`python -I` 运行、路径当参数传。
