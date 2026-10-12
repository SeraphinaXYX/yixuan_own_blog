---
title: "Baby Rev — 用 dis 还原一条 T9 短信 (FortID CTF)"
description: 反汇编 Python 3.10 的 chall.pyc，把手机九宫格按键倒推成一句英文，还原出 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---
> 分类：Reverse ｜ 赛事：FortID CTF 2026 ｜ 关键词：Python pyc、CPython 3.10 字节码、dis / xdis、T9 九宫格、sha256 校验
>
> Flag: `FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}`

## 题目背景

题面是一段很随意的对话：

> I've been texting a lot recently, but can't seem to strike a conversation with this person. They keep asking about some kind of flag...

附件只有一个 `chall.pyc`。文件头四个字节是 `6f 0d 0d 0a`，magic 值 `0x0d6f = 3439`，正是 **CPython 3.10** 的字节码。题目的关键词 "texting"（发短信）已经埋好了伏笔。

## 分析

我手上的解释器是 Python 3.14，它的 marshal 格式和 3.10 不兼容，直接 `marshal.load` 会报 `bad marshal data (unknown type code)`。我也没有 3.10 的解释器、decompyle3 / uncompyle6 在 3.14 上也装不动。好在本机已经装了 **xdis**（跨版本字节码解析库），它能脱离运行时直接把 3.10 的 code object 解析出来、静态反汇编。

这一步很重要：pyc 是**下载来的不可信数据**，绝不能直接 `import` 或执行它。我把解析脚本放在 scratchpad（不是题目目录），用参数把路径传进去，xdis 只做解析不做执行。

反汇编后 `co_consts` 里的常量已经把逻辑说得明明白白：

```
consts: (..., ('t9',), <code nope>, 'pls text me the flag :P\n> ', 81,
         'FortID{', '}', '_', <listcomp>, <listcomp>, '-', -1,
         '33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566',
         'utf-8',
         '3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c',
         '*\\0/* I knew you could do it! ^5')
names: (string, hashlib, sha256, t9text, t9, nope, input, user_input, len,
        startswith, endswith, words, split, w, all, join, get_touchtone,
        encode, hexdigest, print)
```

把主模块字节码读顺，校验逻辑是：

1. `len(user_input) == 81`，否则 `nope()`；
2. 必须 `startswith("FortID{")` 且 `endswith("}")`；
3. `words = user_input[len("FortID{"):-len("}")]`，取出大括号里的内容；
4. 按 `_` 分割，**每个词要么全是小写字母、要么全是数字**（两个列表推导分别检查 `string.ascii_lowercase` 和 `string.digits`）；
5. `words = "-".join(words.split("_"))`，把 `_` 换成 `-`；
6. 核心：`t9.get_touchtone(words)[::-1]` 必须等于常量
   `33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566`；
7. 最后 `sha256(user_input).hexdigest()` 必须等于 `3576c495...357e0c`，全过才打印成功语。

`t9`（来自 `t9text` 模块）的 `get_touchtone` 没在附件里，但题目主题 + 函数名已经点破：这是**手机九宫格（T9）**按键映射——每个字母映射到它所在的拨号键，数字映射成自己，`-` 保留。

## 关键点

- **九宫格键位**：`2=abc 3=def 4=ghi 5=jkl 6=mno 7=pqrs 8=tuv 9=wxyz`。
- 第 6 步做了 `[::-1]`，所以**正向**的按键串是把目标常量整体倒转：
  `66542-3310-47-78455-843-6678-762878-74323-63-8324665649-4-4283-3837-69633`，一共 14 个词。
- "全字母或全数字" 这个约束配合主题，说明这其实是一条用 T9 打出来的英文短信，`3310` 这种含 `1`/`0` 的词因为没有字母能映射到它，只能是**数字原文**。
- 逐词反推（预测式 T9）：`66542→nokia`、`3310→3310`、`47→is`、`78455→still`、`843→the`、`6678→most`、`762878→robust`、`74323→piece`、`63→of`、`8324665649→technology`、`4→i`、`4283→have`、`3837→ever`、`69633→owned`。
- 连起来就是一句吐槽："**nokia 3310 is still the most robust piece of technology i have ever owned**"（诺基亚 3310 是我用过最结实的科技产品）——呼应 "texting" 的梗。

## 利用/求解步骤（贴实际命令/脚本）

静态反汇编（脚本放在 scratchpad，路径当参数传，绝不进题目目录执行）：

```python
# dis_xdis.py
from xdis import load_module
from xdis.disasm import disassemble_file
import sys
res = load_module(sys.argv[1]); co = res[3]
print("version:", res[0], "consts:", co.co_consts)
disassemble_file(sys.argv[1], sys.stdout)
```

```bash
python3 dis_xdis.py fortid_dump/Intro__Baby_Rev/chall.pyc > baby_rev_dis.txt
```

读懂逻辑后，用九宫格把倒转后的按键串逐词翻成英文，再用两个校验（touchtone + sha256）离线验证：

```python
import hashlib, string
words = ["nokia","3310","is","still","the","most","robust","piece",
         "of","technology","i","have","ever","owned"]
inner = "_".join(words)
flag  = "FortID{" + inner + "}"

keypad = {}
for d, letters in {'2':'abc','3':'def','4':'ghi','5':'jkl',
                   '6':'mno','7':'pqrs','8':'tuv','9':'wxyz'}.items():
    for c in letters: keypad[c] = d
tt = "".join(keypad.get(c, c) for c in "-".join(inner.split("_")))

target = "33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566"
assert len(flag) == 81
assert tt[::-1] == target
assert hashlib.sha256(flag.encode()).hexdigest() == \
       "3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c"
print("OK:", flag)
```

运行结果（两条校验都通过，长度正好 81）：

```
len: 81
touchtone match: True
SHA MATCH: True
OK: FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}
```

## Flag

```
FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}
```

## 小结 / 收获

- 跨版本读 pyc：没有对应版本解释器、也没有反编译器时，**xdis** 能直接静态反汇编 3.10 的字节码，读 `co_consts` 往往比硬读指令更快拿到答案。
- 处理下载来的 pyc 一定要当不可信数据：只做静态 `dis`，脚本放别处、路径当参数传，不去 `import` 执行它。
- 这题的"锁"是 touchtone + sha256 双校验：touchtone 把搜索空间缩到"一句合理的英文短信"，sha256 则把大小写/拼写最终钉死。顺着主题（九宫格、发短信）去猜词，比盲目爆破快得多。
