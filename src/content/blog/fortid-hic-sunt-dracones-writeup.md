---
title: "Hic Sunt Dracones — 龙形曲线包裹的 Koblitz 编码 (FortID CTF)"
description: FortID CTF Cryptography 题：flag 先用 Koblitz 把每个字符编码成椭圆曲线上的点，再用「龙形分形」做一次仿射位移；位移序列与起点无关，差分即可离线还原明文。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Cryptography ｜ 赛事：FortID CTF 2026 ｜ 关键词：Koblitz 编码、龙形曲线（dragon curve）、海龟图形共享状态、位移差分、离线还原
>
> Flag: `FortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}`（题目把 `output.txt` 和源码都给了，我在本机完全离线算出，下面展示脚本与结果）

## 题目背景

题面只有一句「You have been warned... 🐉」加一个 handout。解开后是 `chall.py`、`patch.py`、`output.txt` 和 Dockerfile。核心逻辑：

- `chall.py` 把 `turtle` 替换成一个自写的 `HeadlessTurtle`（无界面海龟），然后 clone 了 GitHub 上的 `awnonbhowmik/Dragon-Crypto`（`patch.py` 对其 `koblitz.py` 打了补丁，把素数 `p` 变成 256 位随机素数并修好了求平方根）。
- flag 的每个字符先经 `koblitz_encoder` 编码成椭圆曲线 `y²=x³+ax+b (mod p)` 上的一个点，再经 `dragon.dragon_render` 做一次「龙形曲线行走」变换，最后把所有点用 `point_to_character` 拼成字符串写进 `output.txt`。
- 私钥 `private_key = (size, iterations, angle, a, b)`，其中 `size` 是 128 位随机数、`iterations ∈ [10,15)`、`angle ∈ {0,180}`。

## 分析

先把 `Dragon-Crypto` 按 Dockerfile 指定的 commit `046ad8d` clone 下来并手动套用 `patch.py`，再把它当成**不可信依赖**放进独立目录、脚本放另一处、`python -I` 运行。

**Koblitz 这一层几乎是明文。** 看 `koblitz.py`：`k=20`，字符 `m` 的编码点横坐标 `x_m = m*20 + j`（`j∈[1,19]`，取第一个能开平方的 `j`）。解码器直接 `chr(floor((x-1)/20))`。也就是说——**只要拿回每个点的横坐标，就能逐字符还原明文**，完全不需要知道 `a,b,p`。

**龙形这一层是一个「与起点无关」的固定位移。** `dragon_render` 每次 `goto(起点)` 重置位置，但**不重置海龟朝向**，且 `ob` 是跨所有点共享的同一个对象。`HeadlessTurtle.forward` 只沿四个轴向走（朝向恒为 90° 的倍数）。因此第 `i` 个点的输出 = 起点 + 位移 `D_i`，而 `D_i` 只取决于 `(size, iterations, angle)` 和「此前累计的朝向」，**与该点的坐标无关**。换句话说存在一个确定的位移序列 `D_0, D_1, …`，对所有点都一样。

解析 `output.txt` 后看得很清楚：78 个点，横坐标**偶数位是小整数（4 位数）、奇数位是约 41 位的大数（±）**；纵坐标全是 ~77 位大数。原因是补丁后 Koblitz 的纵坐标本身就是 mod 256 位素数的平方根（~2²⁵⁶），所以纵坐标被 Koblitz 自身主宰，对解码没用；真正有用的是横坐标：

- 偶数位点 `D_x = 0`，所以横坐标**直接就是 Koblitz 的 x**（小整数，直接解码出字符）。
- 奇数位点 `D_x = ±size·N`（一个固定大常数，符号交替），横坐标 = Koblitz_x ± 常数。

## 关键漏洞 / 关键点

1. **海龟朝向在多次 `dragon_render` 之间被共享、不重置** → 位移只是一个跟下标有关的确定序列，和被加密的点无关，因此可整体差分消掉。
2. **Koblitz 横坐标直接泄露字符**（`chr((x-1)//20)`），根本不用恢复曲线参数。
3. 私钥空间极小：`iterations` 只有 5 个取值、`angle` 只有 2 个，`size` 可从数据反解。

## 利用步骤（贴我实际运行过的脚本）

思路：我自己复刻 `turn_sequence_generator` 和 `HeadlessTurtle`（都是自包含的），用 `size=1` 跑出「单位位移序列」`ux[i]`（即每个点横向净步数）。真正位移 `D_x[i] = size·ux[i]`。再用奇数位点反解 `size`，然后对所有点 `Koblitz_x = x_end − size·ux[i]`，最后解码。

```python
# solve_hsd.py（核心片段）——与挑战完全一致的 turn_sequence_generator / HeadlessTurtle 已在前面复刻
def unit_x(iterations, angle, count):
    ob = HT(); steps = turn_sequence_generator(iterations)[:-1]; u = []
    for _ in range(count):
        ob.goto(0, 0); ob.left(angle)           # 位置重置、朝向不重置
        for s in steps:
            if s == 'f': ob.forward(1)
            elif s == 'r': ob.right(90)
            elif s == 'l': ob.left(90)
        u.append(round(ob.xcor()))
    return u

xs = [int(v) for v in open('output.txt').read().strip().split('XY')[0].split('X')[1:]]
n = len(xs)
valid = lambda kx: 1 <= kx <= 2560 and kx % 20 != 0     # x_m = m*20+j, j∈[1,19]
for iters in range(8, 16):
    for angle in (0, 180):
        ux = unit_x(iters, angle, n)
        # 位移为 0 的点（偶数位）横坐标是小整数，模式必须对上
        if not all((ux[i] == 0) == (abs(xs[i]) < 10**6) for i in range(n)):
            continue
        oi = next(i for i in range(n) if ux[i] != 0)     # 第一个奇数位点
        for kob in range(1, 2561):                        # 猜它的 Koblitz x
            num = xs[oi] - kob
            if num % ux[oi]: continue
            size = num // ux[oi]
            kxs = [xs[i] - size * ux[i] for i in range(n)]
            if all(valid(k) for k in kxs):
                msg = ''.join(chr((k - 1)//20) for k in kxs)
                if msg.startswith("FortID{") and msg.endswith("}"):
                    print(iters, angle, size.bit_length(), msg)
```

运行（题目文件路径当参数传，`-I` 隔离）：

```
$ python3 -I solve_hsd.py .../output.txt
iters=14 angle=0 size_bits=128
FLAG: FortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}
```

`angle=0` 和 `angle=180` 都给出同一个 flag（符号对称，差分时被吸收），`size` 果然是 128 位，`iterations=14`，全部自洽。

## Flag

```
FortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}
```

（flag 梗：如果 Don Knuth 把它写在墙上，那拿来做密码一定没问题吧？——正好对应这个看似花哨其实不安全的玩具方案。）

## 小结 / 收获

- 多层「加密」里只要有一层是**与数据无关的确定变换**，就能整体抵消掉。这里的龙形行走因为共享海龟朝向、位移序列固定，直接被差分干掉。
- Koblitz 编码把明文塞进横坐标的高位，天然泄露原字符，`a,b,p` 全程用不上。
- 私钥空间小 + 范围约束（`1≤x≤2560、x mod 20≠0`）+ flag 前后缀（`FortID{…}`）三重过滤，秒定唯一解。
- 处理第三方依赖时严格「题目文件单独目录、脚本另放、`-I` 运行、路径当参数传」，避免 `import` 时踩到投毒模块。
