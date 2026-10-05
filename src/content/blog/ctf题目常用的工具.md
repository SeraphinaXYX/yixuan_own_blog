---
title: CTF题目常用的工具
description: tools
type: resources
pubDate: Oct 05 2026
updatedDate: Oct 05 2026
---
### 一、 通用与基础环境 (Base Environment)

1：操作系统：Kali Linux / Ubuntu：绝大多数安全工具默认集成的 Linux 系统，PWN 与 Web 渗透的首选环境。2：综合编解码/数据处理：

* CyberChef：可以加密，解密然后还可以分析特征
* VS Code / PyCharm：编写 Python 自动化脚本、Payload 构造或爆破脚本。

### 二、 Web 利用 (Web Exploitation)

* 抓包与代理 (核心)：

  * Burp Suite (Community/Professional)：最核心的 Web 安全工具，用于 HTTP 请求截获、修改、重放（Repeater）和字典爆破（Intruder）。
  * Caido / OWASP ZAP：轻量级或开源的抓包替代工具。
* 漏洞扫描与自动化利用：

  * sqlmap：自动化 SQL 注入工具。
  * Dirsearch / ffuf / Gobuster：Web 目录、隐蔽接口、敏感文件爆破工具。
  * tplmap：SSTI（服务端模板注入）自动化利用工具。
* 命令注入与 Webshell 管理：

  * 蚁剑 (AntSword) / 冰蝎 (Behinder) / 哥斯拉 (Godzilla)：Webshell 蚁剑/动态加密管理终端。

### 三、 二进制利用 (Pwn)

* 交互与脚本编写：

  * pwntools (Python 库)：Pwn 脚本编写的绝对核心，提供网络连接（`remote`）、内存数据打包（`p64`/`p32`）、模式匹配（`cyclic`）等功能。   
* 动态调试：

  * GDB + pwndbg / GEF / peda：Linux 动态调试器，配合 `pwndbg` 插件可以直观查看栈结构、寄存器、堆 Chunk 和 ROP 链。   
* 静态分析与二进制检查：

  * checksec：检查 ELF 二进制文件开启了哪些防护机制（NX, Canary, PIE, RELRO）。   
  * ROPgadget / ropper：自动寻找二进制文件中用于 ROP 链构造的代码片段（Gadgets）。
  * one_gadget：寻找 libc 中可直接获取 Shell 的 `one_gadget` 地址。

### 四、 逆向工程 (Reverse Engineering)

* 反汇编与逆向分析：

  * IDA Pro：逆向界的标杆工具，强大的反汇编与 C 语言伪代码还原功能。
  * Ghidra：NSA 开源的免费逆向工具，同样支持强大的伪代码还原。
  * Binary Ninja：现代化的逆向分析软件，中间语言（IL）表现优异。
* Windows 动态调试与脱壳：

  * x64dbg / x32dbg：Windows 下主流的 32/64 位动态调试器。
  * OllyDbg (OD)：经典的 32 位 Windows 调试工具。
  * de4dot：.NET 程序的脱壳与反混淆工具。
  * dnSpy / ILSpy：.NET 反编译与动态调试神器。
* 移动端逆向：

  * JADX / JEB：Android APK 反编译与伪代码查看工具。
  * Frida：动态 Hook 框架，用于运行时修改逻辑、绕过检测。

### 五、 数字取证与隐写 (Forensics & Stego)

* 流量分析：

  * Wireshark：抓包与 PCAP 流量分析利器，支持 HTTP/TCP 跟踪流与提取传输文件。
  * tshark / tcpdump：命令行版本的流量处理工具。
* 文件提取与分析：

  * binwalk / foremost：扫描并提取文件中拼接或嵌入的其他文件（如隐藏压缩包）。
  * 010 Editor / HxD：Hex 十六进制编辑器，用于分析文件头、修补图片宽高或模板分析。
  * exiftool：查看文件（特别是图片）的 EXIF 元数据。
* 图像与音频隐写：

  * StegSolve：图片通道切换、色阶调整、LSB 隐写提取。
  * zsteg：专门用于 PNG/BMP 图片 LSB 隐写的命令行自动化扫描工具。
  * Audacity：音频编辑器，用于查看频谱图（Spectrogram）或波形隐写。
* 内存与磁盘取证：

  * Volatility (v2 / v3)：内存取证框架，用于从 `.raw` / `.vmem` 内存转储中提取进程、命令行、提取文件。
  * FTK Imager / Autopsy：磁盘镜像分析与文件恢复工具。

### 六、 密码学 (Crypto)

* 编程与环境：

  * SageMath：基于 Python 的高级数学计算系统，处理格密码（Lattice）、RSA 复杂数论计算、椭圆曲线（ECC）等密码学问题的必备工具。
  * Python (PyCryptodome / sympy / gmpy2)：密码学脚本编写常用库。
* 自动化爆破与分析：

  * RsaCftTool：针对各种常见 RSA 漏洞（小公钥指数、共模攻击、低解密指数等）的自动化攻击工具。
  * John the Ripper / Hashcat：强大的 Hash 密码爆破工具。
  * Factordb (网站)：在线大数分解数据库，用于查找已知的大合数分解因子。

### 学习建议

新手入门不需要一次性安装所有工具，建议先确定一个方向（如 Web 或 Pwn），把该方向的核心“三剑客”（如 Pwn 的 `GDB+pwndbg` + `pwntools` + `IDA`；Web 的 `Burp Suite` + `Python` + `Dirsearch`）用熟，再根据做题过程中遇到的具体需求补
