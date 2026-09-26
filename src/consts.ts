// Place any global data in this file.
// You can import this data from anywhere in your site by using the `import` keyword.

export const SITE_TITLE = "yixuan's blog";
export const SITE_DESCRIPTION =
	'Personal website and blog of Yixuan Xie (谢奕轩) — NTU CS student, projects, blog, and contact.';

/** Giscus 评论 — 在 .env 或 Vercel 中配置，详见 ADMIN_SETUP.md */
export const GISCUS = {
	repo: 'SeraphinaXYX/yixuan_own_blog',
	repoId: import.meta.env.PUBLIC_GISCUS_REPO_ID ?? '',
	category: 'General',
	categoryId: import.meta.env.PUBLIC_GISCUS_CATEGORY_ID ?? '',
	mapping: 'pathname',
	sharedMapping: 'specific',
	sharedTerm: '/blog/comments/',
	theme: 'preferred_color_scheme',
	lang: 'zh-CN',
};
