---
title: "Melankonimir — EXIF 里藏着「这张图是生成的」的全部证据 (FortID CTF)"
description: FortID CTF OSINT 题：一张「废弃医院」照片，但 EXIF 的 UserComment 完整记录了它的文生图 prompt、seed 与 Civitai 模型，地理定位是陷阱。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：OSINT ｜ 赛事：FortID CTF 2026 ｜ 关键词：EXIF、UserComment、生成式图像、Civitai 元数据、反定位陷阱
>
> Flag:（OSINT 题需实时调查，本文给出完整解题方法；此处不编造 flag。但我从本地图片 EXIF 里提取到了确定的生成元数据，见下文。）

## 题目背景

题目只给一张 `handout.jpg`（1024×1024）和一句济慈的诗：

> *She dwells with Beauty—Beauty that must die.*

出自济慈《Ode on Melancholy（忧郁颂）》，和挑战名 **Melankonimir**（melankolija / 忧郁）呼应。图片内容：一间**废弃医院病房**——剥落的天花板、破窗、生锈的病床、墙上涂鸦（能看到 `BUS` 字样）、地上玻璃碎片。第一反应是"反搜图 + 地理定位某家废弃医院"。但先看元数据，结论完全反转。

## 线索分析（真实 EXIF）

我没有 exiftool，用 `python3 -I` 手搓 TIFF/EXIF 解析器读出以下**真实字段**：

- 字节序 little-endian，只有 7 个 IFD0 条目，**没有相机 Make/Model、没有拍摄时间、没有 GPS**。
- `Software = af2556d6-56b6-442e-ba11-2270f0ec51b6`（一个 UUID，不是正常相机/手机软件名）。
- `Artist = ai`。
- `XResolution/YResolution = 71.983`（非整数，典型的程序生成）。
- 最关键的 **`UserComment`**（UTF-16LE 编码），完整解出一段文生图参数：

```
abandoned hospital, graffiti on walls, dirty empty shelves, broken windows,
broken hospital beds, leaking roof, wet floor, glass shards on floor
Steps: 8, Sampler: euler, CFG scale: 1, Seed: 264476182, Size: 1024x1024,
Created Date: 2026-09-28T15:44:17.546378Z,
Civitai resources: [{"type":"checkpoint","modelVersionId":2442439,
  "modelName":"Z Image Turbo","modelVersionName":"Turbo"}],
Civitai metadata: {"workflow":"txt2img","priority":"low",
  "outputFormat":"jpeg","ecosystem":"ZImageTurbo", ...,
  "seed":264476182,"prompt":"abandoned hospital, graffiti on walls, ...",
  "resources":[{"modelVersionId":2442439,"strength":1,"type":"Checkpoint"}]}
```

也就是说，这张"废弃医院"的每一处细节（涂鸦、空货架、破窗、漏水、玻璃碎片）都是 **prompt 里逐字写明、由文生图模型（Civitai 的 Z Image Turbo）生成的**，创建时间 2026-09-28。画面里的涂鸦文字其实是模型"幻觉"出来的，不对应任何真实地点。

**结论：这是一张完全合成的图，拿去反搜图 / 地理定位真实废弃医院是陷阱。** 这正是题目的"忧郁/虚幻"设定在玩的梗——你以为有一处真实的美景（地点），但"Beauty that must die"，它根本不存在。

## 解题思路 / 该怎么做

面对任何一张 OSINT 图片，**第一步永远是元数据三连**，而不是上来就反搜图：

1. **EXIF 优先**：`exiftool handout.jpg`（没有就用 `python3 -I` 读 TIFF，或 `identify -verbose` / `xxd`）。
   - 看 `Make/Model`（有没有真实设备）、`DateTimeOriginal` + 时区、`GPS*`（经纬度）。
   - 看 `Software`、`Artist`、`UserComment`、`ImageDescription`、以及 PNG 的 `tEXt`/`parameters` chunk——**生成式图片的 prompt/seed 经常原样写在这里**（Automatic1111、ComfyUI、Civitai 都会写）。
2. 一旦发现 `Software` 是 UUID、`Artist=ai`、分辨率非整数、且有 `Steps/Sampler/CFG/Seed/Civitai resources` 这类字段 → **立刻判定为合成图**，停止无谓的地理定位。
3. 若题目确实要一个"答案"，合理的方向是**围绕生成链本身做 OSINT**（这些才是可查证的真实信息）：
   - 用 `Seed: 264476182` + `Z Image Turbo`（modelVersionId `2442439`）在 Civitai 上检索该模型版本、该 seed 的公开生成记录 / 作者 / post。
   - 用 `Created Date 2026-09-28T15:44:17Z` 缩小时间线。
   - 核对 prompt 文本是否在某个公开 gallery 原样出现。
   （具体 flag 需要实时在 Civitai 上检索，本文不臆测。）
4. 视觉上验证"合成"的旁证：直线扭曲、涂鸦字不成词、病床/货架结构不合逻辑、光照矛盾——都佐证 AIGC。

> 注意：以上第 3 点是方法方向，**我没有去 Civitai 实查，不编造"查到了某账号/某图"的结论**。确定的只有上面从 EXIF 里原样读出的生成参数。

## 小结 / 收获

- OSINT 不等于"马上反搜图"。**先读元数据**，常常一步拆穿"这图根本不是拍的"。
- 生成式图片的 prompt/seed/模型几乎都写在 `UserComment` 或 PNG `tEXt` 里，这既能识别合成，也把调查对象从"现实地点"切换到"生成记录"。
- 出题人用济慈的忧郁颂 + 虚构废墟，玩的就是"美必死/此景不存在"的反定位陷阱，读懂文学线索能更快确认方向。
