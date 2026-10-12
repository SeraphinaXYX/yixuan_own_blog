---
title: "Baby OSINT — 一张萨格勒布集会照拆成四问 (FortID CTF)"
description: FortID CTF OSINT 入门题：从 Zrinjevac 公园的一张集会照出发，查活动官方名、同日美食节、公共单车 TikTok 统计，拼出四段式 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：OSINT ｜ 赛事：FortID CTF 2026 ｜ 关键词：EXIF 时间线、克罗地亚地标、克语检索、公共单车开放数据、TikTok
>
> Flag 格式：`FortID{q1:q2:q3:q4}`（全小写英文、空格换下划线、去标点）。OSINT 题需实时调查，本文给出每一问的可操作路径，不编造具体答案。

## 题目背景

题目给一张 `handout.jpeg`，并要求回答四个问题拼成 flag：

1. 图里活动的**确切官方名称**？
2. 同一天在萨格勒布（Zagreb）举办、就在附近、其主办方公开表态支持该活动的**美食节**是哪个？
3. [一个 TikTok 视频](https://www.tiktok.com/@anci26.7_/video/7542843600665644290) 里市长试骑新投放的**公共单车**，哪**一周中的星期几**平均骑行次数最多？
4. 同一地点、同一时刻记录到的这种单车**最多有多少辆**？

## 线索分析（真实 EXIF + 画面）

**EXIF（我手搓 TIFF 解析读出的真实字段）：**

- 设备：`Make = HONOR`，`Model = PTP-N49`（荣耀手机）。
- 拍摄时间：`DateTimeOriginal = 2026:09:05 12:03:02`，时区 `+02:00`（克罗地亚夏令时 CEST）。
- GPS：EXIF 里**存在 GPS IFD 指针，但内容为空**（0 条目，坐标被清掉），所以拿不到经纬度——定位要靠画面。

**画面特征（可用于地理定位）：**

- 成排高大的**悬铃木（platani）林荫道** + 碎石步道 → 萨格勒布 **Zrinjevac（Trg Nikole Šubića Zrinskog，泽林斯基广场）** 的经典样貌。
- 蓝色路牌写克罗地亚语 **`Pješačka zona`（步行区）**，确认在克罗地亚城市核心区。
- 左侧一栋**搭着脚手架在修缮的新古典主义建筑**（Zrinjevac 一带的博物馆/学院类建筑），可作为精确对齐 Google Street View 的锚点。
- 人群举**克罗地亚国旗**、有写标语的横幅、前方立着一张印着某男性头像的展板 → 这是一场**政治集会/游行**，不是普通庆典。

综合 EXIF 日期（2026-09-05）+ 地点（Zrinjevac）：这天萨格勒布确有一场大规模集会。公开报道把 9 月 5 日的游行与**利卡 / 戈斯皮奇（Lika / Gospić）地区的有害废料倾倒危机**联系在一起（媒体出现 "Walk for Lika / Hodaj za Liku" 一类叫法）。**这是研究线索，不是确认答案**——Q1 要"确切官方名称"，必须在克媒（Index.hr、Novi list、24sata 等）核对当天报道里活动的正式名字再按格式化规则写。

## 解题思路 / 该怎么做（逐问）

**Q1 活动官方名称：**
1. 先用画面把地点钉死在 Zrinjevac：反搜图（Yandex/Google Lens）+ 对齐脚手架建筑的 Street View。
2. 用 EXIF 日期 `2026-09-05` 做关键词：克语搜 `Zagreb prosvjed 5. rujna 2026`、`Zrinjevac skup rujan 2026`。
3. 在当天报道里找活动的**正式名称**（横幅/官方页的用词），按题目规则：全小写英文、空格→下划线、去标点。注意要的是官方名，不是媒体口语叫法。

**Q2 同日、附近、主办方表态支持的美食节：**
1. 搜 `Zagreb food festival rujan 2026` / `gastro festival Zagreb 5.9.2026`（Zagreb 常见的有 Burger Festival、Fuliranje、Zagreb Gastro 等）。
2. 锁定**就在 Zrinjevac 附近、且日期覆盖 9/5** 的那个。
3. 关键过滤条件是"**主办方公开表态支持该集会**"——去该美食节的官方 Instagram/Facebook 翻 9 月初的帖子，找声援 Q1 活动的那条，确认是哪个节。

**Q3 公共单车：哪天平均骑行最多：**
1. 从 TikTok `@anci26.7_` 的视频确认是**哪套新投放的公共单车系统**（看车身品牌/涂装/App），以及"市长"是谁（锁定城市=Zagreb）。
2. 找该系统的**开放数据/运营统计**（官网 dashboard、城市 open-data 门户、或 nextbike 类公开 API）。
3. 按星期几聚合骑行次数求平均，取最大的那天（答案是星期几的英文小写，如 `monday`）。

**Q4 同一地点同一时刻最多多少辆：**
1. 同一数据源里看**单站点容量/实时占用**的峰值（通常是 docking/虚拟站点的 `bikes_available` 或快照里同一站最大车辆数）。
2. 取历史快照中单站同时记录到的最大值，即示例里 `8856` 位置上的那种纯数字。

最后按 `FortID{q1:q2:q3:q4}` 拼接。

## 小结 / 收获

- 入门 OSINT 的套路很固定：**EXIF 给时间/设备/时区 → 画面给地点 → 用"时间+地点"喂搜索**。本题 GPS 被清空，但 Zrinjevac 的悬铃木、`Pješačka zona` 路牌、脚手架建筑足以定位。
- 跨语言检索是关键：用克罗地亚语关键词（`prosvjed`、`rujan`、`gastro`）才能命中本地报道。
- Q3/Q4 本质是**开放数据题**：找到官方/第三方的单车统计接口，按维度聚合即可，别被"OSINT"吓到去手数视频。

来源（Q1 方向的背景线索，仅供核对）：[Novi list – Skup na Zrinjevcu](https://www.novilist.hr/?p=533007)、[FrontPages.EU – Croatia protests loom](https://buttondown.com/frontpageseu/archive/croatia-protests-loom-banking-crisis-deepens/)。
