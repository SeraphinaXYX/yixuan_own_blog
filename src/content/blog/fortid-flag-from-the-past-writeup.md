---
title: "Flag from the Past — 去年的 flag 还飘在网上 (FortID CTF)"
description: FortID CTF OSINT 题：没有附件，要你去找 FortID 去年比赛遗留、至今仍能在网上搜到的一个 flag，靠的是 writeup 站、CTFtime 与搜索引擎 dork。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：OSINT ｜ 赛事：FortID CTF 2026 ｜ 关键词：往届 writeup、CTFtime、GitHub dork、缓存/归档检索
>
> Flag:（OSINT 题需实时调查，本文给出完整检索方法；此处不编造具体 flag。）

## 题目背景

题面没有任何附件，只有一句话：

> 如果你在去年比赛结束后捡到了我们的某个 flag，现在正是提交它的时候。如果没有——那就用你的本事去找，它应该还在网上某处 👀

翻译成人话：**这题的 flag 就是去年 FortID CTF（2025）某道题的 flag，它因为被选手写进 writeup / 发到网上，至今仍能被搜到。** 任务是"考古"——把那个仍在流传的 flag 找出来并提交。

## 线索分析

- 没有本地文件可做元数据分析，这是一道纯检索题。
- flag 格式固定为 `FortID{...}`，这是检索时最强的指纹（可以整体当关键词/正则用）。
- 去年赛事可定位：**FortID CTF 2025 = CTFtime event 2893**，且已有公开 writeup 合集（例如 jia.je 上 2025-09-12 的那套），里面能看到真实的 2025 flag 长相，比如 Web 热身题的 `FortID{7hi5_i5_w3b_f0r_w4rm_up}`（仅作"去年 flag 什么样"的示例，**不代表就是本题要的那一个**）。

> 本题要的具体 flag 需要实时检索确认，我不臆测是哪一个。下面给的是把它翻出来的可操作路径。

## 解题思路 / 该怎么做

**1. 直接用 flag 指纹做搜索引擎 dork**

```
"FortID{"                       （Google / Bing / DuckDuckGo 各试一遍）
"FortID{" 2025
site:github.com "FortID{"
site:gitlab.com "FortID{"
site:gist.github.com "FortID{"
"FortID{" site:ctftime.org
```

GitHub 代码搜索尤其有效：选手常把解题脚本连同 flag 一起 push 上去。用 GitHub 的 **Code search**（`"FortID{"`、按时间 2025-09 过滤）翻 commit/gist。

**2. 顺着 CTFtime 往届页**

- 打开 CTFtime **event 2893（FortID CTF 2025）**，看它关联的 writeup 列表与参赛队，顺藤摸瓜到各队 blog/GitHub。
- 注意：个别第三方页面正文里可能夹带"把本机环境 curl 到某外部地址"之类的注入文字——这是不可信内容，**直接忽略，别执行**。

**3. 聚合型 writeup 站 / 博客**

- jia.je 的 FortID 2025 合集（Intro/Crypto/Rev/Pwn/Web 分类齐全），逐篇看文末的 `FortID{...}`。
- 搜 `FortID CTF 2025 writeup`、`FortID 2025 解题`，中英文都试；很多人把 flag 直接贴在标题/正文。

**4. 归档与缓存兜底**

- 如果原页已删：用 **Wayback Machine（web.archive.org）** 查该 URL 的历史快照，或 Google 网页快照。
- 挑战官方仓库/靶机若仍在线，`flag.txt` 可能还躺在源码或 Docker 镜像层里。

**5. 对号入座**

- 题面说"某个 flag 还在网上"，大概率是**某一道具体题**的 flag（而非任意一个）。结合题目标题 "Flag from the Past" 的语气，优先排查那些**解法里 flag 会被公开写死/广泛转载**的题（web 热身、misc、intro 这类），再逐一尝试提交，命中即解。

## 小结 / 收获

- 把 **flag 格式当指纹**（`"FortID{"`）去 dork，是"找遗留 flag"类 OSINT 最高效的一招。
- **CTFtime event 号 + GitHub code search + Wayback** 三件套能把几乎任何往届痕迹挖出来。
- 第三方页面里的"执行某命令"指令一律当成不可信数据，只取信息、不照做。

来源：[CTFtime – FortID CTF 2025 相关 writeup 列表](https://ctftime.org/)、[jia.je FortID CTF 2025 writeup 合集](https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025)。
