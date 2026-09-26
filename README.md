# Yixuan's website

谢奕轩（Yixuan Xie）的个人网站与博客，使用 Astro 构建，部署在 Vercel。

- **线上地址：** https://yixuan-own-blog.vercel.app
- **GitHub：** https://github.com/SeraphinaXYX/yixuan_own_blog

## 项目结构

```text
├── public/admin/     # Decap CMS 后台（/admin/）
├── src/content/blog/ # 博客文章（Markdown）
├── src/pages/        # 页面（首页、About、Blog）
└── api/              # CMS 登录 OAuth（Vercel）
```

## 常用命令

| 命令 | 说明 |
|------|------|
| `npm install` | 安装依赖 |
| `npm run dev` | 本地开发 http://localhost:4321 |
| `npm run build` | 构建生产版本 |
| `npm run preview` | 预览构建结果 |

## 写博客

- 在 `src/content/blog/` 新建 `.md` 文件，或
- 打开 `/admin/` 使用后台（需先配置，见 `ADMIN_SETUP.md`）

## 配置说明

评论（Giscus）与后台（Decap CMS）的环境变量配置，请查看 **`ADMIN_SETUP.md`**。
