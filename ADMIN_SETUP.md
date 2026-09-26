# Yixuan's website — 后台与评论配置说明

本站：**https://yixuan-own-blog.vercel.app**  
仓库：**SeraphinaXYX/yixuan_own_blog**  
作者：**Yixuan Xie（谢奕轩）**

本站包含：

- **博客文章**：`src/content/blog/`
- **Giscus 评论**：文章底部
- **Decap CMS 后台**：`/admin/`（浏览器里写文章）

---

## 1. Giscus 评论

1. 打开 GitHub 仓库：`SeraphinaXYX/yixuan_own_blog`
2. **Settings → General → Features** → 开启 **Discussions**
3. 打开 [https://giscus.app](https://giscus.app)
4. 填写仓库名，语言选 **中文** 或 **English**，分类选 **General**
5. 复制 **Repository ID** 和 **Category ID**
6. 在 **Vercel** → 你的项目 → **Settings → Environment Variables** 添加：
   - `PUBLIC_GISCUS_REPO_ID` =（来自 giscus.app）
   - `PUBLIC_GISCUS_CATEGORY_ID` =（来自 giscus.app）
7. 重新部署（Redeploy）

配置完成后，每篇博客文章底部会显示评论区。

---

## 2. Decap CMS 后台（`/admin/`）

### 创建 GitHub OAuth App

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**
2. **Application name（应用名称）：** `Yixuan's website 内容后台`
3. **Homepage URL：** `https://yixuan-own-blog.vercel.app`
4. **Authorization callback URL：** `https://yixuan-own-blog.vercel.app/api/callback`
5. 创建后复制 **Client ID**，并生成 **Client Secret**

### 在 Vercel 添加环境变量

| 变量名 | 值 |
|--------|-----|
| `GITHUB_OAUTH_CLIENT_ID` | OAuth App 的 Client ID |
| `GITHUB_OAUTH_CLIENT_SECRET` | OAuth App 的 Client Secret |
| `SITE_URL` | `https://yixuan-own-blog.vercel.app` |

保存后请 **重新部署**。

### 使用后台

1. 打开 `https://yixuan-own-blog.vercel.app/admin/`
2. 点击 **Login with GitHub**（使用有仓库写入权限的账号：`SeraphinaXYX`）
3. 新建或编辑博客文章
4. 点击 **Publish** → 自动提交到 GitHub → Vercel 自动更新网站

### 在文章中嵌入视频

在正文编辑器中粘贴嵌入代码，例如 YouTube：

```html
<iframe width="100%" height="400" src="https://www.youtube.com/embed/视频ID" frameborder="0" allowfullscreen></iframe>
```

Bilibili 请使用分享菜单里的嵌入链接。

---

## 3. 不用后台，本地写文章（可选）

在 `src/content/blog/` 新建 `我的文章.md`：

```markdown
---
title: '文章标题'
description: '简短摘要'
pubDate: 'May 31 2026'
---

正文内容……
```

然后执行：

```bash
git add .
git commit -m "新文章"
git push origin main
```

---

## 常见问题

| 问题 | 解决方法 |
|------|----------|
| 评论不显示 | 确认已开启 Discussions，并配置 Giscus 环境变量 |
| `/admin` 无法登录 | 检查 OAuth 回调地址与 Vercel 环境变量；GitHub 授权后弹窗空白/无反应 → 确认已部署最新 `api/callback.js` 并完成 Redeploy |
| 授权后弹窗停在空白页 | 多为 OAuth 回调未与 Decap 完成 postMessage 握手，或 `SITE_URL` 与访问域名不一致导致 redirect_uri 不匹配 |
| 后台发布后构建失败 | `pubDate` 格式需为 `May 31 2026` |
| 图片不显示 | 通过后台上传，或放到 `src/assets/blog/` |

---

## 联系方式（网站内容参考）

- 邮箱：yixuan071112@outlook.com
- GitHub：https://github.com/SeraphinaXYX
- LinkedIn：https://www.linkedin.com/in/yixuan-xie-b50932382
- Instagram：@xuan291547
- 项目：[Dream Journey](https://yixuan-your-dream-journey.netlify.app/) · [Canva 介绍](https://yixuanxie.my.canva.site/)
