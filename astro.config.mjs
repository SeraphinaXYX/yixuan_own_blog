// @ts-check

import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import { defineConfig, fontProviders } from 'astro/config';

// The GitHub Pages mirror is served from a subdirectory, so it needs its own
// `site`/`base`. The Actions workflow sets GITHUB_PAGES=true; every other build
// (Vercel, local dev) is unaffected and keeps serving from the domain root.
const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const BASE = isGitHubPages ? '/yixuan_own_blog' : '';

/**
 * Rewrite root-relative links written inside post markdown (e.g. `](/about/)`)
 * so they resolve under the configured base. No-op when BASE is '' — the
 * Vercel output is byte-for-byte unchanged.
 */
function rehypeBaseLinks() {
	const attrFor = { a: 'href', img: 'src' };
	return (tree) => {
		const walk = (node) => {
			const attr = attrFor[node.tagName];
			if (attr && node.properties) {
				const value = node.properties[attr];
				if (
					typeof value === 'string' &&
					value.startsWith('/') &&
					!value.startsWith('//') &&
					!value.startsWith(`${BASE}/`)
				) {
					node.properties[attr] = `${BASE}${value}`;
				}
			}
			for (const child of node.children || []) walk(child);
		};
		walk(tree);
	};
}

// https://astro.build/config
export default defineConfig({
	site: isGitHubPages
		? 'https://seraphinaxyx.github.io/yixuan_own_blog/'
		: 'https://yixuan-own-blog.vercel.app/',
	base: isGitHubPages ? '/yixuan_own_blog/' : '/',
	integrations: [mdx(), sitemap()],
	markdown: { rehypePlugins: [rehypeBaseLinks] },
	fonts: [
		{
			provider: fontProviders.local(),
			name: 'Atkinson',
			cssVariable: '--font-atkinson',
			fallbacks: ['sans-serif'],
			options: {
				variants: [
					{
						src: ['./src/assets/fonts/atkinson-regular.woff'],
						weight: 400,
						style: 'normal',
						display: 'swap',
					},
					{
						src: ['./src/assets/fonts/atkinson-bold.woff'],
						weight: 700,
						style: 'normal',
						display: 'swap',
					},
				],
			},
		},
	],
});
