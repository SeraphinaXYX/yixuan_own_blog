import { getSession } from './_comment-session.js';

const REPOSITORY_OWNER = 'SeraphinaXYX';
const REPOSITORY_NAME = 'yixuan_own_blog';

export default async function handler(req, res) {
	res.setHeader('Cache-Control', 'no-store');
	const session = getSession(req);
	if (!session?.token || !session?.login) {
		res.status(401).json({ authenticated: false, commented: false });
		return;
	}

	try {
		let discussionNumber = Number(req.query.discussion);
		if (!Number.isSafeInteger(discussionNumber) || discussionNumber < 1) {
			const path = safeBlogPath(req.query.path);
			if (!path) {
				res.status(400).json({
					authenticated: true,
					commented: false,
					login: session.login,
					error: 'A valid blog path is required.',
				});
				return;
			}
			discussionNumber = await findDiscussionNumber(session.token, path);
		}
		if (!discussionNumber) {
			res.status(200).json({
				authenticated: true,
				commented: false,
				login: session.login,
				error: 'No GitHub discussion exists for this post yet. Leave the first comment below, then try again.',
			});
			return;
		}
		const commented = await hasComment(session.token, session.login, discussionNumber);
		res.status(200).json({ authenticated: true, commented, login: session.login });
	} catch (error) {
		console.error('Comment verification failed', error);
		res.status(502).json({
			authenticated: true,
			commented: false,
			login: session.login,
			error: 'Could not verify the GitHub comment. Please try again.',
		});
	}
}

function safeBlogPath(value) {
	if (typeof value !== 'string' || value.length > 512) return null;
	// A post slug may contain non-ASCII characters (Chinese titles), and the
	// browser hands us `location.pathname` percent-encoded, so the segment can
	// legitimately contain `%` and multi-byte characters. Restrict the shape
	// (exactly one segment under /blog/, no query, fragment or traversal)
	// rather than the alphabet.
	if (!/^\/blog\/[^/?#]+\/$/.test(value)) return null;
	if (value.includes('..')) return null;
	return value;
}

/**
 * Giscus stores the discussion title from its `pathname` mapping, which may be
 * the percent-encoded or the decoded form depending on how the page was loaded.
 * Compare against every equivalent spelling so Chinese slugs match either way.
 */
function discussionTermVariants(path) {
	const variants = new Set();
	const add = (value) => {
		if (typeof value === 'string' && value) variants.add(normalizeDiscussionTerm(value));
	};
	add(path);
	let decoded = null;
	try {
		decoded = decodeURIComponent(path);
		add(decoded);
	} catch {
		// leave the raw form as the only variant
	}
	if (decoded) {
		try {
			add(encodeURI(decoded));
		} catch {
			// ignore
		}
	}
	return variants;
}

async function findDiscussionNumber(token, path) {
	const expectedTerms = discussionTermVariants(path);
	let cursor = null;
	do {
		const data = await githubGraphql(
			token,
			`query($owner: String!, $name: String!, $cursor: String) {
				repository(owner: $owner, name: $name) {
					discussions(first: 100, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
						nodes { number title }
						pageInfo { hasNextPage endCursor }
					}
				}
			}`,
			{ owner: REPOSITORY_OWNER, name: REPOSITORY_NAME, cursor },
		);
		const discussions = data.repository?.discussions;
		const match = discussions?.nodes.find((discussion) =>
			expectedTerms.has(normalizeDiscussionTerm(discussion.title)),
		);
		if (match) return match.number;
		if (!discussions?.pageInfo.hasNextPage) return null;
		cursor = discussions.pageInfo.endCursor;
	} while (cursor);
	return null;
}

function normalizeDiscussionTerm(value) {
	return value.trim().replace(/^\/+|\/+$/g, '');
}

async function hasComment(token, login, discussionNumber) {
	let cursor = null;
	do {
		const data = await githubGraphql(
			token,
			`query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
					repository(owner: $owner, name: $name) {
						discussion(number: $number) {
							comments(first: 100, after: $cursor) {
								nodes { author { login } }
								pageInfo { hasNextPage endCursor }
							}
						}
					}
				}`,
			{
				owner: REPOSITORY_OWNER,
				name: REPOSITORY_NAME,
				number: discussionNumber,
				cursor,
			},
		);

		const comments = data.repository?.discussion?.comments;
		if (!comments) return false;
		if (comments.nodes.some((comment) => comment.author?.login?.toLowerCase() === login.toLowerCase())) {
			return true;
		}
		if (!comments.pageInfo.hasNextPage) return false;
		cursor = comments.pageInfo.endCursor;
	} while (cursor);

	return false;
}

async function githubGraphql(token, query, variables) {
	const response = await fetch('https://api.github.com/graphql', {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
			'User-Agent': 'yixuan-own-blog',
		},
		body: JSON.stringify({ query, variables }),
	});
	const data = await response.json();
	if (!response.ok || data.errors) {
		throw new Error(data.errors?.[0]?.message || `GitHub returned ${response.status}`);
	}
	return data.data;
}
