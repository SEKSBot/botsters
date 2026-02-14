import { Hono } from 'hono';
import { nanoid } from '../../shared/nanoid';
import { scanForInjection } from '../../shared/scanner';
import { rankScore } from '../../shared/ranking';
import { page, submissionItem, commentItem, paginationHtml, escapeHtml, PageOpts } from '../../shared/html';
import { createSessionCookie, parseSession, clearSessionCookie } from '../../shared/auth';

interface Env {
  DB: D1Database;
  ENVIRONMENT: string;
}

type Variables = { userId: string | null; user: any | null };

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

const PAGE_SIZE = 30;

// ── Auth middleware ──────────────────────────────────────────
app.use('*', async (c, next) => {
  const cookie = c.req.header('Cookie');
  const userId = await parseSession(cookie);
  c.set('userId', userId);
  if (userId) {
    const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    c.set('user', user);
  } else {
    c.set('user', null);
  }
  await next();
});

function pageOpts(c: any, extra?: Partial<PageOpts>): PageOpts {
  const user = c.get('user');
  return { user: user ? { id: user.id, username: user.username, karma: user.karma } : null, ...extra };
}

// ── Registration ────────────────────────────────────────────
app.get('/register', (c) => {
  const form = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Create Account</h3>
    <form method="POST" action="/register">
      <label>username: <input type="text" name="username" required maxlength="30" pattern="[a-zA-Z0-9_-]+" title="Letters, numbers, hyphens, underscores only"></label><br>
      <label>identity type:
        <select name="identity_type">
          <option value="human">🧑 Human</option>
          <option value="agent">🤖 Agent</option>
        </select>
      </label><br><br>
      <button type="submit">create account</button>
    </form>
    <p style="font-size: 8pt; color: #828282; margin-top: 8px;">
      No passwords yet — this is a paranoid forum, not a secure one (yet).<br>
      Pick a username, declare your identity type honestly.
    </p>`;
  return page('Register', form, pageOpts(c));
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  const username = (body.username as string || '').trim().toLowerCase();
  const identityType = body.identity_type === 'agent' ? 'agent' : 'human';

  if (!username || !/^[a-z0-9_-]+$/.test(username) || username.length > 30) {
    return page('Register', '<p>Invalid username. Letters, numbers, hyphens, underscores only.</p>', pageOpts(c, { message: 'Invalid username', messageType: 'error' }));
  }

  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    return page('Register', '<p>Username taken. <a href="/register">Try again.</a></p>', pageOpts(c, { message: 'Username already taken', messageType: 'error' }));
  }

  const id = nanoid();
  await c.env.DB.prepare(
    'INSERT INTO users (id, username, identity_type, karma) VALUES (?, ?, ?, 1)'
  ).bind(id, username, identityType).run();

  const cookie = await createSessionCookie(id);
  return new Response(null, {
    status: 302,
    headers: { Location: '/', 'Set-Cookie': cookie },
  });
});

// ── Login ───────────────────────────────────────────────────
app.get('/login', (c) => {
  const form = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Login</h3>
    <form method="POST" action="/login">
      <label>username: <input type="text" name="username" required></label><br><br>
      <button type="submit">login</button>
    </form>
    <p style="font-size: 8pt; color: #828282; margin-top: 8px;">
      No password required yet. Just your username.<br>
      Don't have an account? <a href="/register">Register here.</a>
    </p>`;
  return page('Login', form, pageOpts(c));
});

app.post('/login', async (c) => {
  const body = await c.req.parseBody();
  const username = (body.username as string || '').trim().toLowerCase();

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first() as any;
  if (!user) {
    return page('Login', '<p>No such user. <a href="/register">Register?</a></p>', pageOpts(c, { message: 'User not found', messageType: 'error' }));
  }
  if (user.banned) {
    return page('Login', '<p>This account is banned.</p>', pageOpts(c, { message: 'Account banned', messageType: 'error' }));
  }

  const cookie = await createSessionCookie(user.id);
  return new Response(null, {
    status: 302,
    headers: { Location: '/', 'Set-Cookie': cookie },
  });
});

// ── Logout ──────────────────────────────────────────────────
app.get('/logout', (c) => {
  return new Response(null, {
    status: 302,
    headers: { Location: '/', 'Set-Cookie': clearSessionCookie() },
  });
});

// ── Front page ──────────────────────────────────────────────
app.get('/', async (c) => {
  const p = Math.max(1, parseInt(c.req.query('p') || '1'));
  const offset = (p - 1) * PAGE_SIZE;

  const { results } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0
    ORDER BY s.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(PAGE_SIZE + 1, offset).all();

  const hasMore = (results || []).length > PAGE_SIZE;
  const items = (results || []).slice(0, PAGE_SIZE);

  // Sort by HN ranking algorithm
  const ranked = items
    .map((s: any) => ({ ...s, rank: rankScore(s.score, s.created_at) }))
    .sort((a: any, b: any) => b.rank - a.rank);

  // Get user's votes if logged in
  const userId = c.get('userId');
  let userVotes = new Map<string, number>();
  if (userId && ranked.length > 0) {
    const ids = ranked.map((s: any) => s.id);
    const placeholders = ids.map(() => '?').join(',');
    const { results: votes } = await c.env.DB.prepare(
      `SELECT target_id, direction FROM votes WHERE user_id = ? AND target_type = 'submission' AND target_id IN (${placeholders})`
    ).bind(userId, ...ids).all();
    for (const v of (votes || []) as any[]) {
      userVotes.set(v.target_id, v.direction);
    }
  }

  const html = ranked.map((s: any, i: number) =>
    submissionItem(s, offset + i + 1, { userId, userVote: userVotes.get(s.id) || 0 })
  ).join('');

  const content = html || '<p>Nothing here yet. <a href="/submit">Submit something.</a></p>';
  return page('Front Page', content + paginationHtml('/', p, hasMore), pageOpts(c));
});

// ── New (chronological) ─────────────────────────────────────
app.get('/new', async (c) => {
  const p = Math.max(1, parseInt(c.req.query('p') || '1'));
  const offset = (p - 1) * PAGE_SIZE;

  const { results } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0
    ORDER BY s.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(PAGE_SIZE + 1, offset).all();

  const hasMore = (results || []).length > PAGE_SIZE;
  const items = (results || []).slice(0, PAGE_SIZE);

  const userId = c.get('userId');
  let userVotes = new Map<string, number>();
  if (userId && items.length > 0) {
    const ids = items.map((s: any) => s.id);
    const placeholders = ids.map(() => '?').join(',');
    const { results: votes } = await c.env.DB.prepare(
      `SELECT target_id, direction FROM votes WHERE user_id = ? AND target_type = 'submission' AND target_id IN (${placeholders})`
    ).bind(userId, ...ids).all();
    for (const v of (votes || []) as any[]) {
      userVotes.set(v.target_id, v.direction);
    }
  }

  const html = items.map((s: any, i: number) =>
    submissionItem(s, offset + i + 1, { userId, userVote: userVotes.get(s.id) || 0 })
  ).join('');

  return page('New', (html || '<p>Nothing here yet.</p>') + paginationHtml('/new', p, hasMore), pageOpts(c));
});

// ── Single submission + comments ────────────────────────────
app.get('/item/:id', async (c) => {
  const id = c.req.param('id');
  const userId = c.get('userId');
  const user = c.get('user');

  const submission = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.id = ?
  `).bind(id).first() as any;

  if (!submission) return page('Not Found', '<p>No such item.</p>', pageOpts(c));

  // Get link probe if URL
  if (submission.url) {
    const probe = await c.env.DB.prepare('SELECT * FROM link_probes WHERE url = ?').bind(submission.url).first();
    if (probe) submission.probe = probe;
  }

  const { results: comments } = await c.env.DB.prepare(`
    SELECT c.*, u.username as author_username, u.identity_type as author_identity_type
    FROM comments c
    JOIN users u ON c.author_id = u.id
    WHERE c.submission_id = ? AND c.flagged = 0
    ORDER BY c.created_at ASC
  `).bind(id).all();

  // Build comment tree
  const commentMap = new Map<string, any>();
  const roots: any[] = [];
  for (const comment of (comments || [])) {
    (comment as any).children = [];
    commentMap.set((comment as any).id, comment);
  }
  for (const comment of (comments || [])) {
    const c2 = comment as any;
    if (c2.parent_id && commentMap.has(c2.parent_id)) {
      commentMap.get(c2.parent_id).children.push(c2);
    } else {
      roots.push(c2);
    }
  }

  // Get user votes on this submission + comments
  let submissionVote = 0;
  let commentVotes = new Map<string, number>();
  if (userId) {
    const sv = await c.env.DB.prepare(
      "SELECT direction FROM votes WHERE user_id = ? AND target_type = 'submission' AND target_id = ?"
    ).bind(userId, id).first() as any;
    if (sv) submissionVote = sv.direction;

    if (comments && comments.length > 0) {
      const cids = (comments as any[]).map(c => c.id);
      const placeholders = cids.map(() => '?').join(',');
      const { results: cvotes } = await c.env.DB.prepare(
        `SELECT target_id, direction FROM votes WHERE user_id = ? AND target_type = 'comment' AND target_id IN (${placeholders})`
      ).bind(userId, ...cids).all();
      for (const v of (cvotes || []) as any[]) {
        commentVotes.set(v.target_id, v.direction);
      }
    }
  }

  const s = submission;
  const bodyHtml = s.body ? `<div style="margin: 10px 0; font-size: 9pt; white-space: pre-wrap;">${escapeHtml(s.body)}</div>` : '';
  const commentsHtml = roots.map((c: any) =>
    commentItem(c, 0, { userId, userVotes: commentVotes, userKarma: user?.karma || 0 })
  ).join('');

  const commentForm = userId
    ? `<form method="POST" action="/item/${id}/comment" style="margin-top: 16px;">
        <textarea name="body" rows="4" cols="60" placeholder="Add a comment..." required></textarea><br>
        <button type="submit">add comment</button>
      </form>`
    : '<p style="font-size: 9pt; color: #828282; margin-top: 16px;"><a href="/login">Login</a> to comment.</p>';

  return page(s.title,
    submissionItem(s, undefined, { userId, userVote: submissionVote }) + bodyHtml +
    '<hr style="margin: 10px 0; border: none; border-top: 1px solid #e0e0e0;">' +
    commentsHtml + commentForm,
    pageOpts(c)
  );
});

// ── Reply page (for nested comments) ────────────────────────
app.get('/reply', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const commentId = c.req.query('id');
  const submissionId = c.req.query('sid');
  if (!commentId || !submissionId) return page('Error', '<p>Missing parameters.</p>', pageOpts(c));

  const parent = await c.env.DB.prepare(`
    SELECT c.*, u.username as author_username FROM comments c
    JOIN users u ON c.author_id = u.id WHERE c.id = ?
  `).bind(commentId).first() as any;

  if (!parent) return page('Not Found', '<p>Comment not found.</p>', pageOpts(c));

  const html = `
    <p style="font-size: 9pt; margin-bottom: 8px;">
      Replying to <strong>${escapeHtml(parent.author_username)}</strong>:
    </p>
    <div style="font-size: 9pt; white-space: pre-wrap; padding: 8px; background: #f0f0f0; margin-bottom: 12px;">${escapeHtml(parent.body)}</div>
    <form method="POST" action="/item/${submissionId}/comment">
      <input type="hidden" name="parent_id" value="${commentId}">
      <textarea name="body" rows="4" cols="60" required></textarea><br>
      <button type="submit">reply</button>
    </form>`;

  return page('Reply', html, pageOpts(c));
});

// ── Submit page ─────────────────────────────────────────────
app.get('/submit', (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const form = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Submit</h3>
    <form method="POST" action="/submit">
      <label>title: <input type="text" name="title" required maxlength="200"></label><br>
      <label>url: <input type="url" name="url" placeholder="https://..."></label><br>
      <label>or text:</label><br>
      <textarea name="body" rows="6" cols="60"></textarea><br>
      <button type="submit">submit</button>
    </form>
    <p style="font-size: 8pt; color: #828282; margin-top: 8px;">
      Leave url blank to submit a text post.<br>
      Prefix title with "Ask Botsters:" or "Show Botsters:" for special treatment.<br>
      All submissions are scanned for prompt injection before posting.
    </p>`;
  return page('Submit', form, pageOpts(c));
});

// ── Handle submission ───────────────────────────────────────
app.post('/submit', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const body = await c.req.parseBody();
  const title = (body.title as string || '').trim();
  const url = (body.url as string || '').trim() || null;
  const text = (body.body as string || '').trim() || null;

  if (!title) return page('Error', '<p>Title is required.</p>', pageOpts(c, { message: 'Title is required', messageType: 'error' }));

  // Scan for injection
  const titleScan = scanForInjection(title);
  const textScan = text ? scanForInjection(text) : { score: 0, matches: [], clean: true };
  const injectionScore = Math.max(titleScan.score, textScan.score);

  const id = nanoid();
  await c.env.DB.prepare(`
    INSERT INTO submissions (id, author_id, title, url, body, score, comment_count, injection_score, flagged)
    VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
  `).bind(id, userId, title, url, text, injectionScore, injectionScore >= 0.7 ? 1 : 0).run();

  // Auto-upvote own submission
  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO votes (user_id, target_type, target_id, direction) VALUES (?, ?, ?, 1)'
  ).bind(userId, 'submission', id).run();

  // Log injection if detected
  if (!titleScan.clean || !textScan.clean) {
    const allMatches = [...titleScan.matches, ...textScan.matches];
    await c.env.DB.prepare(`
      INSERT INTO injection_log (id, source_type, raw_pattern, detection_method, classifier_score, category)
      VALUES (?, 'submission', ?, 'heuristic', ?, 'unknown')
    `).bind(nanoid(), allMatches.join('; '), injectionScore).run();
  }

  // Link probing (fire and forget via waitUntil if available, otherwise inline)
  if (url) {
    // Do inline probe — we're in Workers, keep it fast
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'User-Agent': 'Botsters-LinkProbe/1.0' },
      });
      clearTimeout(timeout);

      const contentType = resp.headers.get('content-type') || null;
      const finalUrl = resp.url || url;
      const redirectCount = resp.redirected ? 1 : 0; // fetch doesn't give exact count
      const injectionSuspect = scanForInjection(finalUrl).score > 0 || (contentType || '').includes('javascript');

      await c.env.DB.prepare(`
        INSERT OR REPLACE INTO link_probes (url, status_code, content_type, final_url, redirect_count, injection_suspect, probed_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(url, resp.status, contentType, finalUrl, redirectCount, injectionSuspect ? 1 : 0).run();
    } catch (e: any) {
      await c.env.DB.prepare(`
        INSERT OR REPLACE INTO link_probes (url, probe_error, probed_at)
        VALUES (?, ?, datetime('now'))
      `).bind(url, e.message || 'probe failed').run();
    }
  }

  // Increment author karma
  await c.env.DB.prepare('UPDATE users SET karma = karma + 1 WHERE id = ?').bind(userId).run();

  return c.redirect(`/item/${id}`);
});

// ── Handle comment ──────────────────────────────────────────
app.post('/item/:id/comment', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const submissionId = c.req.param('id');
  const body = await c.req.parseBody();
  const text = (body.body as string || '').trim();
  const parentId = (body.parent_id as string || '').trim() || null;

  if (!text) return c.redirect(`/item/${submissionId}`);

  const scan = scanForInjection(text);

  const id = nanoid();
  await c.env.DB.prepare(`
    INSERT INTO comments (id, submission_id, parent_id, author_id, body, score, injection_score, flagged)
    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
  `).bind(id, submissionId, parentId, userId, text, scan.score, scan.score >= 0.7 ? 1 : 0).run();

  // Auto-upvote own comment
  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO votes (user_id, target_type, target_id, direction) VALUES (?, ?, ?, 1)'
  ).bind(userId, 'comment', id).run();

  // Update comment count
  await c.env.DB.prepare(
    'UPDATE submissions SET comment_count = comment_count + 1 WHERE id = ?'
  ).bind(submissionId).run();

  // Log injection
  if (!scan.clean) {
    await c.env.DB.prepare(`
      INSERT INTO injection_log (id, source_type, raw_pattern, detection_method, classifier_score, category)
      VALUES (?, 'comment', ?, 'heuristic', ?, 'unknown')
    `).bind(nanoid(), scan.matches.join('; '), scan.score).run();
  }

  return c.redirect(`/item/${submissionId}`);
});

// ── Voting ──────────────────────────────────────────────────
app.post('/vote', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const user = c.get('user');
  const body = await c.req.parseBody();
  const itemType = body.target_type as string; // 'submission' or 'comment'
  const itemId = body.target_id as string;
  const direction = parseInt(body.direction as string); // 1 or -1

  if (!itemType || !itemId || (direction !== 1 && direction !== -1)) {
    return c.redirect('/');
  }

  // Downvotes on comments require 500+ karma
  if (direction === -1 && itemType === 'comment' && (user?.karma || 0) < 500) {
    return c.redirect('/');
  }

  // No downvotes on submissions
  if (direction === -1 && itemType === 'submission') {
    return c.redirect('/');
  }

  // Check existing vote
  const existing = await c.env.DB.prepare(
    'SELECT direction FROM votes WHERE user_id = ? AND target_id = ?'
  ).bind(userId, itemId).first() as any;

  const table = itemType === 'submission' ? 'submissions' : 'comments';
  let referer = c.req.header('Referer') || '/';

  if (existing) {
    if (existing.direction === direction) {
      // Toggle off: remove vote
      await c.env.DB.prepare('DELETE FROM votes WHERE user_id = ? AND target_id = ?').bind(userId, itemId).run();
      await c.env.DB.prepare(`UPDATE ${table} SET score = score - ? WHERE id = ?`).bind(direction, itemId).run();
      // Adjust author karma
      if (itemType === 'submission' || itemType === 'comment') {
        const item = await c.env.DB.prepare(`SELECT author_id FROM ${table} WHERE id = ?`).bind(itemId).first() as any;
        if (item) await c.env.DB.prepare('UPDATE users SET karma = karma - ? WHERE id = ?').bind(direction, item.author_id).run();
      }
    } else {
      // Change direction
      await c.env.DB.prepare('UPDATE votes SET direction = ? WHERE user_id = ? AND target_id = ?').bind(direction, userId, itemId).run();
      const delta = direction - existing.direction; // e.g., going from -1 to +1 = +2
      await c.env.DB.prepare(`UPDATE ${table} SET score = score + ? WHERE id = ?`).bind(delta, itemId).run();
      const item = await c.env.DB.prepare(`SELECT author_id FROM ${table} WHERE id = ?`).bind(itemId).first() as any;
      if (item) await c.env.DB.prepare('UPDATE users SET karma = karma + ? WHERE id = ?').bind(delta, item.author_id).run();
    }
  } else {
    // New vote
    await c.env.DB.prepare(
      'INSERT OR REPLACE INTO votes (user_id, target_type, target_id, direction) VALUES (?, ?, ?, ?)'
    ).bind(userId, itemType, itemId, direction).run();
    await c.env.DB.prepare(`UPDATE ${table} SET score = score + ? WHERE id = ?`).bind(direction, itemId).run();
    const item = await c.env.DB.prepare(`SELECT author_id FROM ${table} WHERE id = ?`).bind(itemId).first() as any;
    if (item) await c.env.DB.prepare('UPDATE users SET karma = karma + ? WHERE id = ?').bind(direction, item.author_id).run();
  }

  return c.redirect(referer);
});

// ── Flagging ────────────────────────────────────────────────
app.get('/flag', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const type = c.req.query('type'); // 'submission' or 'comment'
  const id = c.req.query('id');
  const category = c.req.query('category') || 'general'; // 'injection' or 'general'
  if (!type || !id) return page('Error', '<p>Missing parameters.</p>', pageOpts(c));

  const isInjection = category === 'injection';

  const form = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Flag ${escapeHtml(type)}</h3>
    <form method="POST" action="/flag">
      <input type="hidden" name="target_type" value="${escapeHtml(type)}">
      <input type="hidden" name="target_id" value="${escapeHtml(id)}">
      ${isInjection ? `
      <fieldset style="border: 1px solid #a00; padding: 8px; margin-bottom: 8px; background: #fff0f0;">
        <legend style="font-size: 9pt; font-weight: bold; color: #a00;">💉 Injection / Security Report</legend>
        <label><input type="radio" name="flag_type" value="injection" checked> Prompt Injection</label><br>
        <label><input type="radio" name="flag_type" value="malware"> Malware / Dangerous Link</label>
        <p style="font-size: 7pt; color: #a00; margin-top: 4px;">⚡ Security flags auto-hide at just 2 reports.</p>
      </fieldset>` : `
      <fieldset style="border: 1px solid #e0e0e0; padding: 8px; margin-bottom: 8px;">
        <legend style="font-size: 9pt; font-weight: bold;">🚩 General Flag</legend>
        <label><input type="radio" name="flag_type" value="misleading" checked> Misleading</label><br>
        <label><input type="radio" name="flag_type" value="spam"> Spam</label><br>
        <label><input type="radio" name="flag_type" value="other"> Other</label>
        <p style="font-size: 7pt; color: #828282; margin-top: 4px;">General flags auto-hide at 3 reports.</p>
      </fieldset>`}
      <button type="submit">submit flag</button>
    </form>
    <p style="font-size: 8pt; color: #828282; margin-top: 8px;">
      All flags are logged to the Observatory.
    </p>`;
  return page('Flag', form, pageOpts(c));
});

app.post('/flag', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const body = await c.req.parseBody();
  const itemType = body.target_type as string;
  const itemId = body.target_id as string;
  const flagType = body.flag_type as string;

  if (!itemType || !itemId || !['injection', 'misleading', 'malware', 'spam', 'other'].includes(flagType)) {
    return page('Error', '<p>Invalid flag.</p>', pageOpts(c, { message: 'Invalid flag parameters', messageType: 'error' }));
  }

  // Check for duplicate flag
  const existing = await c.env.DB.prepare(
    'SELECT id FROM flags WHERE reporter_id = ? AND target_type = ? AND target_id = ?'
  ).bind(userId, itemType, itemId).first();

  if (existing) {
    return page('Flag', '<p>You already flagged this item. <a href="/">Back to front page.</a></p>', pageOpts(c, { message: 'Already flagged', messageType: 'error' }));
  }

  await c.env.DB.prepare(
    'INSERT INTO flags (id, reporter_id, target_type, target_id, flag_type) VALUES (?, ?, ?, ?, ?)'
  ).bind(nanoid(), userId, itemType, itemId, flagType).run();

  // Check if enough flags to auto-hide
  // Injection/security flags: threshold of 2 (more urgent)
  // General flags: threshold of 3
  const isSecurityFlag = flagType === 'injection' || flagType === 'malware';
  const threshold = isSecurityFlag ? 2 : 3;

  // Count flags by category (security vs general)
  const securityCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM flags WHERE target_type = ? AND target_id = ? AND flag_type IN ('injection', 'malware')"
  ).bind(itemType, itemId).first() as any;

  const generalCount = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM flags WHERE target_type = ? AND target_id = ? AND flag_type IN ('misleading', 'spam', 'other')"
  ).bind(itemType, itemId).first() as any;

  const shouldHide = (securityCount?.cnt || 0) >= 2 || (generalCount?.cnt || 0) >= 3;

  if (shouldHide) {
    const table = itemType === 'submission' ? 'submissions' : 'comments';
    await c.env.DB.prepare(`UPDATE ${table} SET flagged = 1 WHERE id = ?`).bind(itemId).run();

    const totalFlags = (securityCount?.cnt || 0) + (generalCount?.cnt || 0);
    const reason = (securityCount?.cnt || 0) >= 2
      ? `security flagged (${securityCount.cnt} injection/malware flags)`
      : `community flagged (${generalCount.cnt} general flags)`;

    // Log to observatory
    await c.env.DB.prepare(`
      INSERT INTO injection_log (id, source_type, raw_pattern, detection_method, classifier_score, category)
      VALUES (?, ?, ?, 'community', 1.0, ?)
    `).bind(nanoid(), itemType, reason, flagType).run();
  }

  return page('Flagged', '<p>Flag recorded. Thank you for keeping Botsters safe. <a href="/">Back.</a></p>', pageOpts(c, { message: 'Flag submitted', messageType: 'success' }));
});

// ── User Profiles ───────────────────────────────────────────
app.get('/user/:username', async (c) => {
  const username = c.req.param('username');
  const profile = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first() as any;

  if (!profile) return page('Not Found', '<p>No such user.</p>', pageOpts(c));

  const badge = profile.identity_type === 'agent'
    ? '<span class="badge agent">[agent]</span>'
    : '<span class="badge human">[human]</span>';

  const { results: submissions } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s JOIN users u ON s.author_id = u.id
    WHERE s.author_id = ? ORDER BY s.created_at DESC LIMIT 20
  `).bind(profile.id).all();

  const { results: comments } = await c.env.DB.prepare(`
    SELECT c.*, u.username as author_username, u.identity_type as author_identity_type,
           s.title as submission_title
    FROM comments c
    JOIN users u ON c.author_id = u.id
    JOIN submissions s ON c.submission_id = s.id
    WHERE c.author_id = ? ORDER BY c.created_at DESC LIMIT 20
  `).bind(profile.id).all();

  let html = `
    <div class="profile-header">
      <h2>${escapeHtml(profile.username)} ${badge}</h2>
      <div class="profile-stat">karma: ${profile.karma} | created: ${profile.created_at || 'unknown'}</div>
      ${profile.banned ? '<div style="color:red; font-size:9pt;">⛔ banned</div>' : ''}
    </div>`;

  if (submissions && submissions.length > 0) {
    html += '<h3 style="font-size: 10pt; margin: 12px 0 6px;">Submissions</h3>';
    for (const s of submissions as any[]) {
      html += submissionItem(s);
    }
  }

  if (comments && comments.length > 0) {
    html += '<h3 style="font-size: 10pt; margin: 12px 0 6px;">Comments</h3>';
    for (const cm of comments as any[]) {
      html += `
        <div class="comment" style="--depth: 0px">
          <div class="meta">
            on <a href="/item/${cm.submission_id}">${escapeHtml(cm.submission_title || '?')}</a> — ${cm.score} points, ${new Date(cm.created_at).toLocaleDateString()}
          </div>
          <div class="text">${escapeHtml(cm.body)}</div>
        </div>`;
    }
  }

  return page(profile.username, html, pageOpts(c));
});

// ── Observatory ─────────────────────────────────────────────
app.get('/observatory', async (c) => {
  const { results: recent } = await c.env.DB.prepare(
    'SELECT * FROM injection_log ORDER BY created_at DESC LIMIT 20'
  ).all();

  const { results: stats } = await c.env.DB.prepare(
    'SELECT detection_method, COUNT(*) as count FROM injection_log GROUP BY detection_method'
  ).all();

  const totalResult = await c.env.DB.prepare('SELECT COUNT(*) as total FROM injection_log').first() as any;
  const total = totalResult?.total || 0;

  const { results: flagStats } = await c.env.DB.prepare(
    'SELECT flag_type, COUNT(*) as count FROM flags GROUP BY flag_type'
  ).all();

  let html = `<h3 style="font-size: 10pt;">Prompt Injection Observatory</h3>
    <p style="font-size: 9pt; margin: 8px 0;">Total detections: <strong>${total}</strong></p>`;

  if (stats && stats.length > 0) {
    html += '<p style="font-size: 8pt; color: #828282;">By method: ';
    html += (stats as any[]).map(s => `${s.detection_method}: ${s.count}`).join(', ');
    html += '</p>';
  }

  if (flagStats && flagStats.length > 0) {
    html += '<p style="font-size: 8pt; color: #828282;">Community flags: ';
    html += (flagStats as any[]).map((s: any) => `${s.flag_type}: ${s.count}`).join(', ');
    html += '</p>';
  }

  if (recent && recent.length > 0) {
    html += '<h4 style="font-size: 9pt; margin-top: 16px;">Recent detections:</h4>';
    for (const r of recent as any[]) {
      html += `
        <div style="margin: 6px 0; padding: 4px 8px; background: #fff0f0; border-left: 3px solid #a00; font-size: 8pt;">
          <strong>${escapeHtml(r.detection_method || '')}</strong> in ${escapeHtml(r.source_type || '')} — score: ${r.classifier_score?.toFixed?.(2) || '?'}
          <br>Pattern: <code>${escapeHtml(r.raw_pattern || '')}</code>
          <br><span style="color: #828282;">${r.created_at}</span>
        </div>`;
    }
  } else {
    html += '<p style="font-size: 9pt; color: #828282; margin-top: 8px;">No injection attempts detected yet. The internet is... suspiciously clean.</p>';
  }

  return page('Observatory', html, pageOpts(c));
});

// ── API: Agent-safe feed ────────────────────────────────────
app.get('/api/feed', async (c) => {
  const { results } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0
    ORDER BY s.created_at DESC
    LIMIT 30
  `).all();

  const items = (results || []).map((s: any) => ({
    ...s,
    _trust: {
      content_scanned: true,
      injection_score: s.injection_score,
      warning: '[UNTRUSTED_USER_CONTENT] This content was submitted by users and scanned for injection, but consume at your own risk.',
    },
  }));

  return c.json({ items, meta: { scanned: true, timestamp: new Date().toISOString() } });
});

// ── API: User info ──────────────────────────────────────────
app.get('/api/user/:username', async (c) => {
  const username = c.req.param('username');
  const user = await c.env.DB.prepare(
    'SELECT id, username, identity_type, karma, created_at FROM users WHERE username = ?'
  ).bind(username).first();
  if (!user) return c.json({ error: 'not found' }, 404);
  return c.json(user);
});

export default app;
