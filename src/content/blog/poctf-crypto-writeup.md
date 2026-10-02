---
title: poctf-crypto-writeup
description: 总结
type: knowledge
pubDate: Oct 02 2026
updatedDate: Oct 02 2026
---
1. 多表代换密码（Polyalphabetic Substitution）

这是整个家族的根。先理解它的对立面——单表代换（比如凯撒密码）：整篇用同一个规则，A 永远变成 D。缺点是字母频率不变，用频率分析一下就破了。

多表代换用一个密钥，让每个位置用不同的替换规则，同一个字母在不同位置变成不同的密文。这样频率被打散，更难破。维吉尼亚、Beaufort 都属于这一类。

2. 维吉尼亚密码（Vigenère）—— 家族的基准

把字母看成数字（A=0, B=1, …, Z=25），密钥循环使用：

\- 加密：C = (P + K) mod 26

\- 解密：P = (C − K) mod 26

mod 26（模 26）是关键——字母表是环形的，Z 再加 1 回到 A。

3. Beaufort 密码 —— 本题的主角

信里那句 "reciprocal tableau which bears your name" 指的就是它。公式和维吉尼亚反过来：

\- 加解密同一个公式：结果 = (K − 密文/明文) mod 26

维吉尼亚解密 │ P = C − K │ 加密解密公式不同              

Beaufort     │ P = K − C │ 加密=解密，互逆（reciprocal） 

"reciprocal（互逆）"就是指：同一套操作，加密和解密是同一个动作。这正是题目给的识别线索——看到"互逆""reciprocal""以某人命名的表格"就想到 Beaufort。

4. Tabula Recta（维吉尼亚方阵 / 表格）

"tableau（表格）"指的是一张 26×26 的字母方阵。手工加解密时查这张表：行是密钥字母、列是明文字母，交叉点就是密文。Beaufort 查表的方式略有不同（从明文字母找到密钥字母所在行，读出列号），这就是"reciprocal tableau"。计算机里直接用上面的模运算公式，不用查表。

5. 密钥（Key）的作用与来源

多表密码的全部安全性都在密钥上。密钥对了，秒解；不知道密钥，就得去猜周期、做分析。

这题的巧妙在于密钥藏在视觉里——花名边框带 ★ 的花首字母拼成 COBWEB。这是 CTF 常见套路：密钥往往藏在题目的图像、文字、元数据里，"find the key"是独立的一关。

6. 已知明文攻击 / Crib（最实用的技巧）

这是最该学会的一招。我们知道 flag 一定以 POCTF{ 开头，而密文以 NAZDZ{ 开头——这段\*\*已知明文（crib）\*\*让我们能反推密钥：

K = (P + C) mod 26（Beaufort 求密钥）→ 算出 COBWE

两个用处：

\- 不知道密钥时，用 crib 直接把密钥的前几位算出来；

\- 验证猜测：拿花名拼出的 COBWEB，用 crib 一验证开头解成 POCTF，就确认"密码类型 + 密钥"都对——正式解密前先自检，密码题必备习惯。
