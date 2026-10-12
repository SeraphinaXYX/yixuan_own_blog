---
title: "Meteor Shower — 从 NES ROM 里挖出隐藏彩蛋 (FortID CTF)"
description: 分析一个 iNES 格式的 NES ROM，用 tile 索引解码文字层，挖出藏在彩蛋里的 flag 短语。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---
> 分类：Reverse ｜ 赛事：FortID CTF 2026 ｜ 关键词：NES、iNES 头、NROM、tile/图块索引编码、CHR 字库、彩蛋文本
>
> Flag: `FortID{bacon_and_eggs_five_strips_at_a_time}`

## 题目背景

题面是一句《回到未来》味十足的台词：

> Great Scott! The biggest meteor storm in the galaxy is headed straight for your sector. ☄️ 🚀
>
> **Note:** wrap the phrase into `FortID{}`, and use `_` to separate the words.

附件是 `meteor_shower.nes`——一个红白机（NES/FC）游戏 ROM。README 已经把解法形态说清楚了：**找到一句短语，自己包进 `FortID{}`、用 `_` 分词**。所以目标不是算 hash，而是把 ROM 里藏着的文字挖出来。

## 分析

先看文件头，确认它确实是标准 iNES ROM：

```
00000000: 4e45 531a 0201 0000  NES.............
```

- 魔数 `4E 45 53 1A` = `NES\x1a`；
- `02` = 2 个 16KB 的 PRG-ROM（共 32KB，即 NROM-256）；
- `01` = 1 个 8KB 的 CHR-ROM（图块/字库）；
- flag 字节为 0，mapper 0（NROM）。

布局因此很清楚：文件偏移 `0x10` 起是 32KB 程序（PRG，映射到 CPU `0x8000–0xFFFF`），`0x8010` 起是 8KB 图形（CHR）。`16 + 32768 + 8192 = 40976`，与文件大小完全吻合。

`strings` 先扫一遍，PRG 里 `0x640` 附近出现一堆看着像文字又不是 ASCII 的东西，而 `0x8410` 之后全是 8×8 的位图点阵——那是 CHR 字库。于是重点落在 PRG 里那段 "伪文字"。

`xxd -s 0x600` 看这段：字节集中在 `0x00`、`0xff`、`0x80–0xbf` 这几档。这是 NES 文本的典型存法——**不是 ASCII，而是 tile（图块）索引**：屏幕上每个字就是 CHR 里一块 8×8 图块，PRG 里存的是图块编号。

## 关键点

- 试映射：`0x00` 当空格、`0xff` 当换行/分页、`0x80` 开始连续映射字母。把 `0x80→'a'` 一代入，`93 8e → "to"`、`8c 8e 95 84 → "move"`，立刻读通，说明字母表从 `0x80` 线性排布。
- `0xb0–0xbf` 是标点图块。为确认它们到底是什么符号，我直接把对应 CHR 图块渲染成点阵来看：`0x80` 画出来是 "A"，`0xb0` 是 `!`、`0xb1` 是 `.`、`0xb4` 是 `-`、`0xb5` 是 `&`。这样整段文字就能无歧义还原。
- 顺带验证标题：`0x640` 处另一段用的是 "ASCII−1" 编码（每个字节 +1 即还原），`LDSDNQ+1 = METEOR`、`RGNVDQ+1 = SHOWER`，确认游戏名就是 "METEOR SHOWER"。
- 全 ROM 扫一遍这种 tile 编码，有意义的长文本**只有** `0x64e` 这一段，所以 flag 必然出自其中。

解出来的完整文本（`|` 表示换行/分页）：

```
d-pad to move | press start | game over | press start |
mission complete | you survived | congratulations! | press start |
easter egg found! | great job on finding | the easter egg. |
i hope you like | bacon & eggs... | five strips at a time.
```

前面都是普通的游戏 UI（移动提示、game over、通关语）。真正藏起来的是最后那段**彩蛋**：通关后触发 "easter egg found!"，接着是一句吐槽——"i hope you like bacon & eggs... five strips at a time."（培根配鸡蛋，一次煎五条）。这就是要包进 `FortID{}` 的短语。

## 利用/求解步骤（贴实际命令/脚本）

ROM 是**下载来的不可信数据**，全程只做静态读取：脚本放在 scratchpad，用参数把路径传进去，不运行、不加载它。

定位文本段：

```bash
strings -n 4 -t x meteor_shower.nes | head
# 0x640 )LDSDNQ / 0x648 RGNVDQ ...  再往后是 0x64e 的大段文字
xxd -s 0x600 -l 0x320 meteor_shower.nes
```

按 tile 索引解码文字段，并把标点图块渲染出来确认符号：

```python
data = open("meteor_shower.nes", "rb").read()

# 1) 解码 0x64e 文本段：0x00=空格 0xff=换行 0x80+ = 字母
def dec(b):
    if b == 0xff: return "\n"
    if b == 0x00: return " "
    if 0x80 <= b <= 0x9f: return chr(ord('a') + (b - 0x80))
    return "{%02x}" % b          # 标点图块，稍后确认
print("".join(dec(x) for x in data[0x64e:0x72a]))

# 2) 渲染 CHR 图块，确认标点：CHR 从文件 0x8010 起，每块 16 字节、两位平面
CHR = 0x8010
def tile(t):
    base = CHR + t * 16
    p0, p1 = data[base:base+8], data[base+8:base+16]
    for y in range(8):
        print("".join("#" if ((p0[y]>>x)&1 or (p1[y]>>x)&1) else " "
                      for x in range(7, -1, -1)))
for t in (0x80, 0xb0, 0xb1, 0xb4, 0xb5):   # A ! . - &
    print("tile %02x:" % t); tile(t)
```

渲染结果确认 `0x80='A'`、`0xb0='!'`、`0xb1='.'`、`0xb4='-'`、`0xb5='&'`，于是 `bacon {b5} eggs` 就是 "bacon & eggs"。

按 README 的要求把彩蛋短语包起来、`&` 读作 "and"、空格换成 `_`：

```
FortID{bacon_and_eggs_five_strips_at_a_time}
```

> 说明：短语文本是从 ROM 里逐字节解码出来的真实内容（已用 CHR 点阵逐字确认）。彩蛋原句是 "i hope you like bacon & eggs... five strips at a time."，我取其中的核心短语、按题目格式要求去掉寒暄前缀和标点、`&`→`and`、空格→`_`。

## Flag

```
FortID{bacon_and_eggs_five_strips_at_a_time}
```

## 小结 / 收获

- NES ROM 逆向第一步永远是读 iNES 头：PRG / CHR 的大小和布局直接决定去哪找代码、去哪找图。
- NES 上的文字几乎都是 **tile 索引**而非 ASCII，`strings` 只能给线索；真正的解码要先猜出图块到字符的映射（通常从某个基址线性排布），标点则靠**把 CHR 图块渲染成点阵**来确认，避免靠猜。
- 处理陌生 ROM 当不可信数据：只静态解析、脚本与数据分目录、路径当参数传。
- 本题 flag 不走 hash 校验，而是藏在通关后的彩蛋文案里——README 的 "wrap the phrase" 提示其实就是在说"去 ROM 里找那句话"。
