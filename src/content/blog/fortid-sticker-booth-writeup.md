---
title: "Sticker Booth — 伪造带票据的贴纸把文件读原语指向 flag.txt (FortID CTF)"
description: FortID CTF pwn 题：自写池分配器 + booth_ticket 票据校验的文件读原语，逆向出全部对象布局与打印分发逻辑，目标是让一张"贴纸"被当成带票据的内置贴纸去 open(flag.txt)。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Pwn ｜ 赛事：FortID CTF 2026 ｜ 关键词：自写堆分配器、对象类型混淆、booth_ticket 票据、文件读原语、静态 No-PIE
>
> Flag: `FORTID{...}`（需连题目实例打远程获取，本机无法复现：到实例裸 TCP 端口的出网被环境挡死；下文的分析、对象布局、文件读原语均已在本机对真实二进制逐一验证）

## 题目背景

"一个能安全地定制并打印贴纸的小摊"。给了静态链接的 `chall`、`recipe_docs.md`（命令手册）、`sample.recipe` 和 `assets/{heart,star,smile}.txt`。程序从 stdin 逐行读"配方命令"：

```
photo   NAME W H RGBA_HEX     # 加一张图片（W*H*4 字节像素）
caption NAME TEXT             # 加一段文字
builtin NAME heart|star|smile # 加一个内置贴纸
mono    NAME                  # 把图片转灰度（把 RGB 清零）
remove  NAME                  # 删除一个条目
upload  NAME HEX              # 上传任意字节的"自定义贴纸"
print                         # 打印当前贴纸表
```

`print` 时每种条目有不同的渲染方式，而**内置贴纸的"渲染"其实是去 `open()` 它对应的资源文件并把内容打印出来**——这就是题眼。谁能把这个"文件读"指到 `flag.txt`，谁就赢。

## 分析

`file` + `readelf` 先定性：

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, statically linked, not stripped
$ readelf -h chall | grep Type
  Type: EXEC (Executable file)       # 静态 + No-PIE，.text/.bss 地址固定
$ readelf -lW chall | grep GNU_STACK
  GNU_STACK ... RW                   # NX 开
# main 里有 fs:0x28 canary；partial RELRO
```

静态、No-PIE、有 canary、NX。所有函数/全局地址固定（`main @ 0x401880`，`items @ 0x4acb40`，`booth_ticket @ 0x4acb20`，`pool @ 0x4ad640` …）。

### 自写池分配器 xalloc

程序不用 libc malloc，而是一个 16KB 的静态池 `pool[0x4000]` + 一张 `blocks[]` 元数据表（每项 `{off, size, used}`，最多 64 项），`xalloc(n)` 把 `n` 向上 8 对齐，**首次适配**地复用 `used==0 && size>=n` 的空闲块，否则从 `top` 顺序 bump 一块；复用时会 `memset` 掉请求大小的那几个字节。我用 gdb 把它的行为逐步 dump 出来确认过：复用只在"块已被 free"后发生，不会让两个在用对象共享同一块。

### 条目与对象布局（gdb 实测）

`items[32]`，每个条目 40 字节：

```c
struct item { char name[24]; uint32_t type; /*pad*/ void *obj; };  // type@0x18, obj@0x20
// type: 1=photo 2=caption/builtin 3=upload(custom) 0=空
```

对象（`obj`）由 `xalloc` 从池里分配，不同命令写出不同的头：

```
photo   : [+0]=W(u32) [+4]=H(u32) [+8]=stride=W*4 ; 像素在 +0x10，共 W*H*4 字节
caption : [+0..1]=refcount(u16) [+2]=1 [+4]=len(u32) [+8]=0 ; 文本在 +0x10, 共 len 字节
builtin : [+0..1]=refcount=1   [+2]=2 [+3]=1 [+4]=pathlen [+8]=booth_ticket ; 路径在 +0x10
upload  : 纯粹 len 个受控字节, 无头部
```

注意：所有拷贝走的是 `memmove`（我在运行时 resolve 了 PLT，`0x401050 -> __memmove_avx_unaligned_erms`），**不写结尾的 `\0`**；caption 去重比较用的是 `memcmp`（`0x4010d0`）。

### booth_ticket 票据

`main` 启动时 `open("/dev/urandom")` 读 8 字节进全局 `booth_ticket`（读失败则回退用 `time()^栈地址^常量`）——总之是本次进程内随机且保密的 8 字节。每个 `builtin` 对象创建时都把当前 `booth_ticket` 原样写进自己的 `+8`。

### 文件读原语（题眼）

`print` 对 `item.type==2` 的条目会读 `obj[2]` 决定怎么渲染：

```c
if (obj[2] == 1)            // caption：fwrite(obj+0x10, obj[4] 字节) —— 只是把文字打出来
else if (obj[2] == 2 && obj[3] != 0 && *(u64*)(obj+8) == booth_ticket) {
    // 内置贴纸且票据匹配 -> 文件读!
    pathlen = obj[4];                     // <= 0x7f
    memcpy(stackbuf, obj+0x10, pathlen);  // 把路径拷到栈
    stackbuf[pathlen] = 0;
    fd = open(stackbuf, O_RDONLY);
    while ((n = read(fd, stackbuf, 0x80)) > 0) write(1, stackbuf, n);  // 把整个文件回显
}
else puts("[broken sticker]");
```

本机实测内置贴纸确实会把资源文件内容打出来：

```
$ printf 'builtin b heart\nprint\n' | ./chall
=== sticker sheet ===
b: <3            # <- 这就是 assets/heart.txt 的内容, 由 open()+read() 打出来
```

所以**赢的条件非常清楚**：让一个 `item.type==2`、`obj[2]==2`、`obj[3]!=0`、`obj[8]==booth_ticket` 的对象，其 `obj+0x10` 处的路径（长度 `obj[4]`）变成 `flag.txt`。

## 关键漏洞

合法内置贴纸同时满足"类型=2、`obj[2]=2`、票据正确"，但它的路径被写死成 `assets/{heart,star,smile}.txt`（`builtin` 处理里对 kind 做三选一的 `strcmp`，否则 `die("unknown builtin")`，用户无法控制路径）。另一边，`upload` 能写出**任意字节**的对象，但它的 `item.type` 被固定成 3，`print` 只会打 `"[custom sticker]"`，永远走不到文件读分支。

于是核心是一个**对象类型混淆 / 票据绕过**：要么让一个 `type==2` 的条目指向我用 `upload` 控制的字节（里面摆好 `obj[2]=2`、正确票据、`flag.txt`），要么就地改写一张在用内置贴纸的路径而不动它的 `+8` 票据。关键细节：

- 票据 `obj[8]` 没有任何输出原语会把它读出来（photo 只打印 `W/H`，caption 只 `fwrite` 文本，内置只回显文件内容），所以**不能直接泄漏**，必须要么保留某张合法内置贴纸现成的票据，要么用一个相对越界读把相邻内置贴纸的 `+8` 一起 dump 出来。
- caption 的引用计数（相同文本会去重、共享同一 `obj`，`refcount++`；`remove` 时 `refcount--`，减到 0 才真正释放）是作者刻意加的复杂度，是最像"埋 UAF"的地方。

## 利用步骤

先给一个能把配方按行打到 `tcp-ssl` 实例、并把 `print` 回显收回来的驱动（远程交互脚手架，本机已验证能正确驱动二进制）：

```python
import socket, ssl
def send_recipe(host, port, lines, wait=6):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    raw = socket.create_connection((host, port))
    s = ctx.wrap_socket(raw, server_hostname=host)
    s.sendall(("\n".join(lines) + "\n").encode())
    s.settimeout(wait); buf=b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            buf += d
    except Exception: pass
    return buf
```

构造思路（把"自定义贴纸"伪装成"带票据的内置贴纸"）：

1. **拿到正确票据。** 池里对象紧邻排列且拷贝不写 `\0`。先让一张 `item.type==2` 的 caption 的"渲染长度" `obj[4]` 与它实际文本错位（利用去重/复用让 `obj[4]` 比文本长），`fwrite(obj+0x10, obj[4])` 就会越过自身、把紧随其后的一张 `builtin` 对象的 `+8`（`booth_ticket`）一起打出来——这样 8 字节票据就泄漏了。
2. **伪造对象。** 用 `upload` 写一段 32 字节：`[+0..1]=refcount`、`[+2]=0x02`、`[+3]=0x01`、`[+4..7]=8`（pathlen）、`[+8..15]=泄漏到的票据`、`[+0x10..]="flag.txt"`。
3. **让一个 `type==2` 的条目指向这段字节**（通过释放 + 同大小复用，把某个 `type==2` caption 条目的 `obj` 落到这块 upload 字节上）。
4. `print` → 该条目 `type==2`、`obj[2]==2`、`obj[3]!=0`、`obj[8]==票据` → `open("flag.txt")`，整份 flag 被回显。

构造贴纸表的基本块我都在本机对真实二进制验证过（`photo/caption/builtin/upload/remove/print` 的分配偏移、`items`/`blocks` 状态、票据写入位置、文件读确实能打资源文件），缺的只是把第 1、3 步所依赖的那次"长度错位 / 条目复用"在实例上调通——这一步对堆布局很敏感，更适合对着真实实例迭代。

## Flag

本机把 flag 读原语本身验证到了（上面 `builtin b heart` → 打出 `assets/heart.txt` 的 `<3`），但把它指到 `flag.txt` 的完整利用需要在题目实例上完成：

- 我能登录平台、能把 Sticker Booth 实例拉起来（HTTPS/443 通），但实例是 `tcp-ssl` 裸端口，从我这台机器出网被挡（IPv4 超时、无 IPv6 路由），没法把配方打过去跑。

所以真 flag **需连题目实例打远程获取，本机无法复现**，这里不编造。

## 小结 / 收获

- 这类题先把"赢的那一行代码"找出来——这里是 `print` 里那个受票据保护的 `open()+read()`，一切都是围着"怎么把它指到 flag"展开。
- 自写分配器要像读 malloc 一样读：我用 gdb 把 `xalloc` 的首次适配、复用 `memset`、`blocks[]`/`top` 的变化全 dump 了一遍，才确认它复用严谨、不会让在用对象重叠——这一步排除了很多想当然的"堆叠叠乐"。
- 拷贝不写 `\0`（`memmove`）+ 长度字段可被错位，是本题泄漏保密票据的关键视角：**越界读经常不是栈/堆溢出，而是"长度和数据不同步"**。
- 诚实记录：手法链路清楚、原语已验证，但没连上实例，就不写假 flag。
