---
title: "Baby Web — 一颗躲猫猫按钮藏不住的前端 flag (FortID CTF)"
description: 前端按钮一碰就跑，但点击回调里就把 flag base64 反着拼好了，静态读 JS 直接还原。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---
> 分类：Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：前端 JS、atob、base64、字符串反转、客户端逻辑
>
> Flag: `FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}`

## 题目背景

题面只有一句俏皮话：

> The flag is only one click away... if you can catch it! 🏃

附件是一个单独的 `index.html`，页面标题叫 *Catch Me If You Can*。打开后中间有一行字「The flag is one click away. You only have to catch the button.」，下面有一颗写着 *Show me the flag* 的按钮。鼠标一靠近，按钮就「嗖」地跑到别的位置，根本点不到——这就是所谓的「catch me」。

## 分析

这类「追着鼠标跑的按钮」几乎都是纯前端把戏：真正的秘密不在服务器，而在页面自己带的 JS 里。所以我没有去手忙脚乱地追按钮，而是直接把 `index.html` 当文本读。

页面底部的 `<script>` 分两段逻辑：

第一段是「逃跑」函数，监听 `mouseenter`，一旦鼠标靠近就把按钮随机挪到视口内的新坐标：

```js
function runAway() {
  const padding = 16;
  const maxX = Math.max(padding, window.innerWidth  - button.offsetWidth  - padding);
  const maxY = Math.max(padding, window.innerHeight - button.offsetHeight - padding);
  button.style.transform = "none";
  button.style.left = `${padding + Math.random() * (maxX - padding)}px`;
  button.style.top  = `${padding + Math.random() * (maxY - padding)}px`;
}
button.addEventListener("mouseenter", runAway);
```

第二段才是关键——`click` 回调里直接把 flag「算」出来写进页面：

```js
button.addEventListener("click", () => {
  const scrambled = [
    "=0XNx81Nx81auFDa38Vdwk3",
    "X1QzXkJHNo91N0g2NfdDMu9V",
    "Nx8lYzc3eElEdy9mR"
  ].join("");
  output.textContent = atob([...scrambled].reverse().join(""));
  ...
});
```

## 关键点 / 解法

逃跑动画只是唬人的；flag 的生成**完全不依赖鼠标是否真的点中按钮**，它就是一串确定性的字符串运算：

1. 把三段字符串拼成一整条 `scrambled`；
2. `[...scrambled].reverse().join("")`——把整条字符串**逐字符反转**；
3. 对反转后的结果做 `atob`，也就是 **base64 解码**。

既然逻辑是纯静态的，我根本不用在浏览器里跟按钮赛跑，直接在本地用一样的运算复现即可。

## 求解步骤（贴实际命令/脚本/读到的关键内容）

我用 Python 原样复刻这三步（拼接 → 反转 → base64 解码）：

```python
import base64
scrambled = "=0XNx81Nx81auFDa38Vdwk3" + "X1QzXkJHNo91N0g2NfdDMu9V" + "Nx8lYzc3eElEdy9mR"
rev = scrambled[::-1]
print("reversed:", rev)
print("decoded :", base64.b64decode(rev).decode())
```

输出：

```
reversed: Rm9ydElEe3czYl8xNV9uMDdfN2g0N19oNHJkXzQ1X3kwdV83aDFua18xN18xNX0=
decoded : FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}
```

反转后得到的那一行以 `Rm9ydEl...` 开头（正是 `FortID` 的 base64），末尾带 `=` 补齐，一切对得上。

如果想在浏览器里「正规」地拿到它，也完全可以绕过逃跑动画：
- 用 DevTools 控制台手动触发 `document.querySelector("#runaway").click()`；
- 或者先 `button.removeEventListener("mouseenter", runAway)` 再点；
- 甚至直接在控制台里跑那段 `atob(...)`。

## Flag

```
FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}
```

## 小结 / 收获

- 只要「秘密」被交付到了客户端，它就不再是秘密——哪怕加了反转、base64、分段拼接这类混淆，本质都是可逆的纯前端运算。
- 遇到「追鼠标的按钮 / 抓不到的元素」，第一反应应该是**读源码**，而不是真的去用交互对抗它；交互层的障碍（动画、`disabled`、`pointer-events`）对攻击者毫无意义。
- flag 文本本身也在「自嘲」：`w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15`（web is not that hard as you think it is），算是出题人的温柔提醒。
