---
title: "OSINT Exam II — 顺着 TBTL 自己的照片把人肉出来 (FortID CTF)"
description: FortID CTF OSINT 题：延续 TBTL 去年的「OSINT 考试」，六道各一张照片，围绕 Blockhouse 公司的办公室、员工、活动做反搜图与地理定位，逐题提交换 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：OSINT ｜ 赛事：FortID CTF 2026 ｜ 关键词：反搜图、EXIF 分流、地理定位、企业注册信息、比赛成绩库、逐题提交
>
> Flag:（OSINT 题需实时调查，本文给出完整解题方法；此处不编造 flag。下文给出每张图我真实提取到的 EXIF/画面线索。）

## 题目背景

题面说你去年拿的"OSINT 认证"过期了，附去年 TBTL-CTF 的 `osint_exam` 链接，要你"重新参加考试续证"。

去年那道题（公开 writeup 可查）的形式是：**6 个问题，每题一张照片，答案都指向 TBTL / Blockhouse Technology 这家公司**（联合办公地点与负责人、Oxford 办公室完整地址、Zagreb 分部地址、某场路跑的城市与完赛成绩、慈善室内五人制比赛名次、某本书的封面自画像……），**在服务里一题一题提交，全部答对后服务返回 flag**。所用技术是反搜图、视觉地理定位、公司官网/团队页、企业注册库、社媒/领英、比赛成绩库、翻译。去年 flag 是 `FortID{C3rt1fi3d_0p3n_50urc3_1n73l1genc3_M45t3r}`。

今年的 `data.zip` 里给了 `q1.png / q2.jpg / q3.jpeg / q5.jpg / q6.mp4 + q6_1.jpeg + q6_2.jpeg`（q4 的素材在服务端），玩法同构。

## 线索分析（逐图真实元数据 + 画面）

**q1.png（赛事完赛奖牌 + 队服）**
- 无 EXIF（JFIF，已去）。画面：橙色挂带 `MEN'S 10K FINISHER`，银色奖牌 `10K MEN'S`，队服胸前印 `BLOCKHOUSE — The Blockhouse Technology`（赞助方=出题公司 TBTL），底部一行 `For your Personalised Event information Pack scan the QR code or visit docs.myrunning.uk/4480`。
- → 对应去年 Q4 那类"路跑城市 + 完赛成绩"。`Men's 10K` + `myrunning.uk` 指向英国的一场 Men's 10K（UK 赛事）。

**q2.jpg（Club-Mate 汽水 + 街边咖啡座）**
- EXIF：`Make=samsung / Model=Galaxy S25 Ultra`，`DateTimeOriginal=2026:05:20 16:34:58`，时区 `+02:00`，`Software=S938BXXS9BZCH`，**无 GPS**。
- 画面：Club-Mate（德国黑客文化饮料）、背景是米黄色 Altbau 公寓楼、自行车、宽人行道 → 典型柏林街景。时区 +02:00 = 中欧夏令时。
- → 一处与公司相关的地点（很可能某分部/落脚城市），靠建筑与街景做地理定位。

**q3.jpeg（展会摊位 + 海报）**
- 无 EXIF（渐进式 JFIF）。画面：手持 Heineken，一张印着 `ditta` logo（旁边还有一个 logo）+ 一位女士拉小提琴的卡通肖像的海报；背景是摊位人像墙 → 像招聘/行业展会的现场漫画速写摊。
- → 从 `ditta` 品牌 + 肖像人物入手识别公司/活动与人物。

**q5.jpg（玻璃办公楼 + 大台阶）**
- EXIF：`Software=Google`（Pixel 手机），`DateTimeOriginal=2026:06:12 13:51:38`，**无 GPS**。
- 画面：现代玻璃办公综合体，中央宽大台阶、两侧种植池，玻璃上隐约有 `Republic`/花体 logo → 像园区式办公开发（英国此类园区很多，如伦敦 Poplar 的 Republic/Import Building 等，需对齐确认）。
- → 地理定位该办公楼/园区。

**q6（夜爬 + 山顶城市夜景）**
- `q6.mp4`：解析 atom，**没有 `udta`/`meta`/`©xyz` 等定位元数据**（位置被清），"CLoc" 只是压缩流里的巧合字节。两张抽帧 `q6_1/q6_2`：一行人打手电**夜爬草坡**，随后站在**裸岩山顶**俯瞰远处城市灯火。
- → 靠山形轮廓 + 山下灯光布局做地理定位（哪座城市旁的哪座山）。

## 解题思路 / 该怎么做

**总体流程（照搬去年考试的结构）：**
1. 每张图先做 **EXIF 分流**：有相机/时间/时区就记下来缩小国家与时间线；有 GPS 直接定位（本套大多被清，只剩时区）。
2. **反搜图**三件套都试：Google Lens、Yandex（对欧洲街景/人脸更强）、Bing Visual。
3. **视觉地理定位**：招牌语言、路牌样式、植被、建筑风格、车牌/品牌，缩到城市再到街道，拿 Street View 对齐。
4. 既然答案都指向 **TBTL/Blockhouse**，就反复回到公司的**官网/团队页、领英、企业注册库、新闻稿**交叉验证人名与地址。
5. 逐题在服务（去年是 `fortid-meta.chals.io` 那类）提交，**全部答对后拿 flag**；注意每题的作答规范（大小写、空格、是否含秒级成绩）。

**逐题落地：**
- **q1**：确认是哪座城市的 `Men's 10K`（`docs.myrunning.uk/4480` 这个 Pack 链接、赛事官网都能验城市与日期）→ 在领英/新闻里找 Blockhouse 的参赛员工 → 去官方成绩库（Great Run/myrunning 结果页）查其完赛时间。多半要给"城市 + 一个或多个完赛成绩"。
- **q2**：由 Altbau 建筑 + Club-Mate + 时区 +02:00 锁定柏林，再用街景对齐那栋楼/那家店，给出地址或地点名。
- **q3**：识别 `ditta` 与海报上的人物（卡通速写常对应真人），确认展会与名次/角色之类的问法。
- **q4**：素材在服务端，按返回的图/提示同法处理。
- **q5**：对齐那座带大台阶的玻璃园区（注意玻璃上的 logo 文字），给出园区/办公室名或地址。
- **q6**：用山形天际线 + 山下灯光图案匹配"城市旁可夜爬的山"（配合 `2026` 的拍摄月份/植被）定位山名。

> 以上只给方向。**我没有去实查出具体人名/地址/成绩，不编造"查到了 X"**；确定的只有上面从文件里原样读到的 EXIF 与画面特征。

## 小结 / 收获

- 这类"考试"题的捷径是**先认出背后的组织**（这里胸前的 BLOCKHOUSE = 出题公司 TBTL），之后所有问题都能围绕它的公开足迹（办公室、员工、赞助的活动）收敛，而不是漫无目的地反搜。
- EXIF 分流永远先做：哪怕 GPS 被清，**时区 + 时间**也能把国家和季节钉死（+02:00、5/6/9 月）。
- 视频同样要查元数据与抽帧；位置被清时，山形轮廓 + 夜景灯光就是地理定位的指纹。

来源（去年考试形式与答案结构的参考）：[TBTL-CTF 2025 osint_exam](https://github.com/blockhousetech/TBTL-CTF/tree/master/2025/Misc/osint_exam/)。
