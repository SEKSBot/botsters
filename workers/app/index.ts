import { Hono } from 'hono';
import { nanoid } from '../../shared/nanoid';
import { scanForInjection } from '../../shared/scanner';
import { rankScore } from '../../shared/ranking';
import { page, submissionItem, commentItem, paginationHtml, escapeHtml, trustBadge, PageOpts } from '../../shared/html';
import { createSessionCookie, parseSession, clearSessionCookie } from '../../shared/auth';
import { trustFlagWeight, TrustTier } from '../../shared/types';

interface Env {
  DB: D1Database;
  AI: any;
  ENVIRONMENT: string;
  TRUST_SECRET: string;
}

type Variables = { userId: string | null; user: any | null };

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

const PAGE_SIZE = 30;

// ── HMAC helpers ────────────────────────────────────────────
async function hmacVerify(secret: string, data: string, signature: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return expected === signature;
}

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
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0
    ORDER BY s.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(PAGE_SIZE + 1, offset).all();

  const hasMore = (results || []).length > PAGE_SIZE;
  const items = (results || []).slice(0, PAGE_SIZE);

  const ranked = items
    .map((s: any) => ({ ...s, rank: rankScore(s.score, s.created_at) }))
    .sort((a: any, b: any) => b.rank - a.rank);

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
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
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
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.id = ?
  `).bind(id).first() as any;

  if (!submission) return page('Not Found', '<p>No such item.</p>', pageOpts(c));

  if (submission.url) {
    const probe = await c.env.DB.prepare('SELECT * FROM link_probes WHERE url = ?').bind(submission.url).first();
    if (probe) submission.probe = probe;
  }

  const { results: comments } = await c.env.DB.prepare(`
    SELECT c.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
    FROM comments c
    JOIN users u ON c.author_id = u.id
    WHERE c.submission_id = ? AND c.flagged = 0
    ORDER BY c.created_at ASC
  `).bind(id).all();

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

// ── Reply page ──────────────────────────────────────────────
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

  const titleScan = scanForInjection(title);
  const textScan = text ? scanForInjection(text) : { score: 0, matches: [], clean: true };
  const injectionScore = Math.max(titleScan.score, textScan.score);

  const id = nanoid();
  await c.env.DB.prepare(`
    INSERT INTO submissions (id, author_id, title, url, body, score, comment_count, injection_score, flagged)
    VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
  `).bind(id, userId, title, url, text, injectionScore, injectionScore >= 0.7 ? 1 : 0).run();

  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO votes (user_id, target_type, target_id, direction) VALUES (?, ?, ?, 1)'
  ).bind(userId, 'submission', id).run();

  if (!titleScan.clean || !textScan.clean) {
    const allMatches = [...titleScan.matches, ...textScan.matches];
    await c.env.DB.prepare(`
      INSERT INTO injection_log (id, source_type, raw_pattern, detection_method, classifier_score, category)
      VALUES (?, 'submission', ?, 'heuristic', ?, 'unknown')
    `).bind(nanoid(), allMatches.join('; '), injectionScore).run();
  }

  if (url) {
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
      const redirectCount = resp.redirected ? 1 : 0;
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

  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO votes (user_id, target_type, target_id, direction) VALUES (?, ?, ?, 1)'
  ).bind(userId, 'comment', id).run();

  await c.env.DB.prepare(
    'UPDATE submissions SET comment_count = comment_count + 1 WHERE id = ?'
  ).bind(submissionId).run();

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
  const itemType = body.target_type as string;
  const itemId = body.target_id as string;
  const direction = parseInt(body.direction as string);

  if (!itemType || !itemId || (direction !== 1 && direction !== -1)) {
    return c.redirect('/');
  }

  if (direction === -1 && itemType === 'comment' && (user?.karma || 0) < 500) {
    return c.redirect('/');
  }

  if (direction === -1 && itemType === 'submission') {
    return c.redirect('/');
  }

  const existing = await c.env.DB.prepare(
    'SELECT direction FROM votes WHERE user_id = ? AND target_id = ?'
  ).bind(userId, itemId).first() as any;

  const table = itemType === 'submission' ? 'submissions' : 'comments';
  let referer = c.req.header('Referer') || '/';

  if (existing) {
    if (existing.direction === direction) {
      await c.env.DB.prepare('DELETE FROM votes WHERE user_id = ? AND target_id = ?').bind(userId, itemId).run();
      await c.env.DB.prepare(`UPDATE ${table} SET score = score - ? WHERE id = ?`).bind(direction, itemId).run();
      const item = await c.env.DB.prepare(`SELECT author_id FROM ${table} WHERE id = ?`).bind(itemId).first() as any;
      if (item) await c.env.DB.prepare('UPDATE users SET karma = karma - ? WHERE id = ?').bind(direction, item.author_id).run();
    } else {
      await c.env.DB.prepare('UPDATE votes SET direction = ? WHERE user_id = ? AND target_id = ?').bind(direction, userId, itemId).run();
      const delta = direction - existing.direction;
      await c.env.DB.prepare(`UPDATE ${table} SET score = score + ? WHERE id = ?`).bind(delta, itemId).run();
      const item = await c.env.DB.prepare(`SELECT author_id FROM ${table} WHERE id = ?`).bind(itemId).first() as any;
      if (item) await c.env.DB.prepare('UPDATE users SET karma = karma + ? WHERE id = ?').bind(delta, item.author_id).run();
    }
  } else {
    await c.env.DB.prepare(
      'INSERT OR REPLACE INTO votes (user_id, target_type, target_id, direction) VALUES (?, ?, ?, ?)'
    ).bind(userId, itemType, itemId, direction).run();
    await c.env.DB.prepare(`UPDATE ${table} SET score = score + ? WHERE id = ?`).bind(direction, itemId).run();
    const item = await c.env.DB.prepare(`SELECT author_id FROM ${table} WHERE id = ?`).bind(itemId).first() as any;
    if (item) await c.env.DB.prepare('UPDATE users SET karma = karma + ? WHERE id = ?').bind(direction, item.author_id).run();
  }

  return c.redirect(referer);
});

// ── Flagging (with trust-weighted thresholds) ───────────────
app.get('/flag', async (c) => {
  const userId = c.get('userId');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  const type = c.req.query('type');
  const id = c.req.query('id');
  const category = c.req.query('category') || 'general';
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
        <p style="font-size: 7pt; color: #a00; margin-top: 4px;">⚡ Security flags — weighted by trust tier. Threshold: 2.0 effective weight.</p>
      </fieldset>` : `
      <fieldset style="border: 1px solid #e0e0e0; padding: 8px; margin-bottom: 8px;">
        <legend style="font-size: 9pt; font-weight: bold;">🚩 General Flag</legend>
        <label><input type="radio" name="flag_type" value="misleading" checked> Misleading</label><br>
        <label><input type="radio" name="flag_type" value="spam"> Spam</label><br>
        <label><input type="radio" name="flag_type" value="other"> Other</label>
        <p style="font-size: 7pt; color: #828282; margin-top: 4px;">General flags — weighted by trust tier. Threshold: 3.0 effective weight.</p>
      </fieldset>`}
      <button type="submit">submit flag</button>
    </form>`;
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

  const existing = await c.env.DB.prepare(
    'SELECT id FROM flags WHERE reporter_id = ? AND target_type = ? AND target_id = ?'
  ).bind(userId, itemType, itemId).first();

  if (existing) {
    return page('Flag', '<p>You already flagged this item. <a href="/">Back to front page.</a></p>', pageOpts(c, { message: 'Already flagged', messageType: 'error' }));
  }

  await c.env.DB.prepare(
    'INSERT INTO flags (id, reporter_id, target_type, target_id, flag_type) VALUES (?, ?, ?, ?, ?)'
  ).bind(nanoid(), userId, itemType, itemId, flagType).run();

  // Trust-weighted flag calculation
  const isSecurityFlag = flagType === 'injection' || flagType === 'malware';

  // Get all flags with reporter trust tiers
  const { results: securityFlags } = await c.env.DB.prepare(`
    SELECT f.*, u.trust_tier FROM flags f
    JOIN users u ON f.reporter_id = u.id
    WHERE f.target_type = ? AND f.target_id = ? AND f.flag_type IN ('injection', 'malware')
  `).bind(itemType, itemId).all();

  const { results: generalFlags } = await c.env.DB.prepare(`
    SELECT f.*, u.trust_tier FROM flags f
    JOIN users u ON f.reporter_id = u.id
    WHERE f.target_type = ? AND f.target_id = ? AND f.flag_type IN ('misleading', 'spam', 'other')
  `).bind(itemType, itemId).all();

  const securityWeight = (securityFlags || []).reduce((sum: number, f: any) => sum + trustFlagWeight(f.trust_tier || 'unverified'), 0);
  const generalWeight = (generalFlags || []).reduce((sum: number, f: any) => sum + trustFlagWeight(f.trust_tier || 'unverified'), 0);

  // injection threshold = 2.0, general threshold = 3.0
  const shouldHide = securityWeight >= 2.0 || generalWeight >= 3.0;

  if (shouldHide) {
    const table = itemType === 'submission' ? 'submissions' : 'comments';
    await c.env.DB.prepare(`UPDATE ${table} SET flagged = 1 WHERE id = ?`).bind(itemId).run();

    const reason = securityWeight >= 2.0
      ? `security flagged (weight: ${securityWeight.toFixed(1)})`
      : `community flagged (weight: ${generalWeight.toFixed(1)})`;

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

  const trust = trustBadge(profile.trust_tier);

  const { results: submissions } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
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

  const currentUser = c.get('user');
  const canVouch = currentUser && (currentUser.trust_tier === 'trusted' || currentUser.trust_tier === 'verified') && currentUser.id !== profile.id;

  let html = `
    <div class="profile-header">
      <h2>${escapeHtml(profile.username)} ${badge}${trust}</h2>
      <div class="profile-stat">karma: ${profile.karma} | trust: ${profile.trust_tier} | created: ${profile.created_at || 'unknown'}</div>
      ${profile.banned ? '<div style="color:red; font-size:9pt;">⛔ banned</div>' : ''}
      ${canVouch ? `<div style="margin-top: 4px;"><a href="/vouch/${escapeHtml(profile.username)}" style="font-size: 9pt;">🤝 Vouch for this user</a></div>` : ''}
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
            on <a href="/item/${cm.submission_id}">${escapeHtml((cm as any).submission_title || '?')}</a> — ${(cm as any).score} points, ${new Date((cm as any).created_at).toLocaleDateString()}
          </div>
          <div class="text">${escapeHtml((cm as any).body)}</div>
        </div>`;
    }
  }

  return page(profile.username, html, pageOpts(c));
});

// ── Vouch system ────────────────────────────────────────────
app.get('/vouch/:username', async (c) => {
  const userId = c.get('userId');
  const user = c.get('user');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  if (!user || (user.trust_tier !== 'trusted' && user.trust_tier !== 'verified')) {
    return page('Vouch', '<p>Only trusted or verified users can vouch for others.</p>', pageOpts(c, { message: 'Insufficient trust tier', messageType: 'error' }));
  }

  const username = c.req.param('username');
  const target = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first() as any;
  if (!target) return page('Not Found', '<p>No such user.</p>', pageOpts(c));
  if (target.id === userId) return page('Vouch', '<p>You cannot vouch for yourself.</p>', pageOpts(c, { message: 'Cannot vouch for yourself', messageType: 'error' }));

  const form = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Vouch for ${escapeHtml(username)}</h3>
    <p style="font-size: 9pt; margin-bottom: 8px;">
      Vouching confirms you trust this user. Vouches require admin approval before the user is upgraded to verified.
    </p>
    <form method="POST" action="/vouch/${escapeHtml(username)}">
      <button type="submit">🤝 Submit vouch</button>
    </form>`;
  return page('Vouch', form, pageOpts(c));
});

app.post('/vouch/:username', async (c) => {
  const userId = c.get('userId');
  const user = c.get('user');
  if (!userId) return new Response(null, { status: 302, headers: { Location: '/login' } });

  if (!user || (user.trust_tier !== 'trusted' && user.trust_tier !== 'verified')) {
    return page('Vouch', '<p>Only trusted or verified users can vouch.</p>', pageOpts(c, { message: 'Insufficient trust tier', messageType: 'error' }));
  }

  const username = c.req.param('username');
  const target = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first() as any;
  if (!target) return page('Not Found', '<p>No such user.</p>', pageOpts(c));

  const existing = await c.env.DB.prepare(
    'SELECT voucher_id FROM vouches WHERE voucher_id = ? AND vouchee_id = ?'
  ).bind(userId, target.id).first();

  if (existing) {
    return page('Vouch', '<p>You already vouched for this user. <a href="/">Back.</a></p>', pageOpts(c, { message: 'Already vouched', messageType: 'error' }));
  }

  await c.env.DB.prepare(
    'INSERT INTO vouches (voucher_id, vouchee_id, admin_approved) VALUES (?, ?, 0)'
  ).bind(userId, target.id).run();

  return page('Vouch', `<p>Vouch submitted for ${escapeHtml(username)}. An admin will review it. <a href="/">Back.</a></p>`, pageOpts(c, { message: 'Vouch submitted', messageType: 'success' }));
});

// ── Admin: Vouches ──────────────────────────────────────────
app.get('/admin/vouches', async (c) => {
  const user = c.get('user');
  if (!user || user.trust_tier !== 'verified') {
    return page('Admin', '<p>Only verified users can access admin pages.</p>', pageOpts(c, { message: 'Access denied', messageType: 'error' }));
  }

  const { results: pending } = await c.env.DB.prepare(`
    SELECT v.*, 
      voucher.username as voucher_username, voucher.trust_tier as voucher_trust,
      vouchee.username as vouchee_username, vouchee.trust_tier as vouchee_trust
    FROM vouches v
    JOIN users voucher ON v.voucher_id = voucher.id
    JOIN users vouchee ON v.vouchee_id = vouchee.id
    WHERE v.admin_approved = 0
    ORDER BY v.created_at DESC
  `).all();

  let html = '<h3 style="font-size: 10pt; margin-bottom: 8px;">Pending Vouches</h3>';

  if (!pending || pending.length === 0) {
    html += '<p style="font-size: 9pt; color: #828282;">No pending vouches.</p>';
  } else {
    for (const v of pending as any[]) {
      html += `
        <div style="padding: 6px 0; border-bottom: 1px solid #e0e0e0; font-size: 9pt;">
          <a href="/user/${escapeHtml(v.voucher_username)}">${escapeHtml(v.voucher_username)}</a>
          <span class="badge ${v.voucher_trust}">[${v.voucher_trust}]</span>
          → vouches for →
          <a href="/user/${escapeHtml(v.vouchee_username)}">${escapeHtml(v.vouchee_username)}</a>
          <span class="badge ${v.vouchee_trust}">[${v.vouchee_trust}]</span>
          <span style="color: #828282; margin-left: 8px;">${v.created_at}</span>
          <form method="POST" action="/admin/vouches/approve" style="display: inline; margin-left: 8px;">
            <input type="hidden" name="voucher_id" value="${v.voucher_id}">
            <input type="hidden" name="vouchee_id" value="${v.vouchee_id}">
            <button type="submit" style="font-size: 8pt; padding: 1px 6px;">✓ Approve</button>
          </form>
          <form method="POST" action="/admin/vouches/reject" style="display: inline; margin-left: 4px;">
            <input type="hidden" name="voucher_id" value="${v.voucher_id}">
            <input type="hidden" name="vouchee_id" value="${v.vouchee_id}">
            <button type="submit" style="font-size: 8pt; padding: 1px 6px; background: #828282;">✗ Reject</button>
          </form>
        </div>`;
    }
  }

  return page('Admin — Vouches', html, pageOpts(c));
});

app.post('/admin/vouches/approve', async (c) => {
  const user = c.get('user');
  if (!user || user.trust_tier !== 'verified') {
    return c.redirect('/');
  }

  const body = await c.req.parseBody();
  const voucherId = body.voucher_id as string;
  const voucheeId = body.vouchee_id as string;

  await c.env.DB.prepare(
    'UPDATE vouches SET admin_approved = 1 WHERE voucher_id = ? AND vouchee_id = ?'
  ).bind(voucherId, voucheeId).run();

  // Upgrade vouchee to verified
  await c.env.DB.prepare(
    "UPDATE users SET trust_tier = 'verified', verified_at = datetime('now'), vouched_by = ? WHERE id = ?"
  ).bind(voucherId, voucheeId).run();

  return c.redirect('/admin/vouches');
});

app.post('/admin/vouches/reject', async (c) => {
  const user = c.get('user');
  if (!user || user.trust_tier !== 'verified') {
    return c.redirect('/');
  }

  const body = await c.req.parseBody();
  const voucherId = body.voucher_id as string;
  const voucheeId = body.vouchee_id as string;

  await c.env.DB.prepare(
    'DELETE FROM vouches WHERE voucher_id = ? AND vouchee_id = ?'
  ).bind(voucherId, voucheeId).run();

  return c.redirect('/admin/vouches');
});

// ── Search ──────────────────────────────────────────────────
app.get('/search', async (c) => {
  const q = (c.req.query('q') || '').trim();
  const userId = c.get('userId');

  if (!q) {
    const form = `
      <h3 style="font-size: 10pt; margin-bottom: 8px;">Search Botsters</h3>
      <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search submissions and comments..." style="width: 400px;" required>
        <button type="submit">search</button>
      </form>`;
    return page('Search', form, pageOpts(c));
  }

  const like = `%${q}%`;

  const { results: submissions } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0 AND (s.title LIKE ? OR s.body LIKE ?)
    ORDER BY s.created_at DESC
    LIMIT 30
  `).bind(like, like).all();

  const { results: comments } = await c.env.DB.prepare(`
    SELECT c.*, u.username as author_username, u.identity_type as author_identity_type,
           s.title as submission_title
    FROM comments c
    JOIN users u ON c.author_id = u.id
    JOIN submissions s ON c.submission_id = s.id
    WHERE c.flagged = 0 AND c.body LIKE ?
    ORDER BY c.created_at DESC
    LIMIT 30
  `).bind(like).all();

  let html = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Search: "${escapeHtml(q)}"</h3>
    <form method="GET" action="/search" style="margin-bottom: 12px;">
      <input type="text" name="q" value="${escapeHtml(q)}" style="width: 400px;">
      <button type="submit">search</button>
    </form>`;

  if (submissions && submissions.length > 0) {
    html += `<h4 style="font-size: 9pt; margin: 8px 0;">Submissions (${submissions.length})</h4>`;
    for (const s of submissions as any[]) {
      html += submissionItem(s, undefined, { userId });
    }
  }

  if (comments && comments.length > 0) {
    html += `<h4 style="font-size: 9pt; margin: 12px 0 8px;">Comments (${comments.length})</h4>`;
    for (const cm of comments as any[]) {
      html += `
        <div class="comment" style="--depth: 0px">
          <div class="meta">
            <a href="/user/${escapeHtml((cm as any).author_username || '?')}">${escapeHtml((cm as any).author_username || '?')}</a>
            on <a href="/item/${(cm as any).submission_id}">${escapeHtml((cm as any).submission_title || '?')}</a>
            — ${new Date((cm as any).created_at).toLocaleDateString()}
          </div>
          <div class="text">${escapeHtml((cm as any).body)}</div>
        </div>`;
    }
  }

  if ((!submissions || submissions.length === 0) && (!comments || comments.length === 0)) {
    html += '<p style="font-size: 9pt; color: #828282;">No results found.</p>';
  }

  return page(`Search: ${q}`, html, pageOpts(c));
});

// ── Observatory (enhanced) ──────────────────────────────────
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

  const { results: categoryStats } = await c.env.DB.prepare(
    'SELECT category, COUNT(*) as count FROM injection_log WHERE category IS NOT NULL GROUP BY category ORDER BY count DESC LIMIT 10'
  ).all();

  // Per-day stats (last 14 days)
  const { results: dailyStats } = await c.env.DB.prepare(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM injection_log
    WHERE created_at >= datetime('now', '-14 days')
    GROUP BY date(created_at)
    ORDER BY day DESC
  `).all();

  // Scanner vs community ratio
  const scannerCount = (stats || []).find((s: any) => s.detection_method === 'heuristic') as any;
  const communityCount = (stats || []).find((s: any) => s.detection_method === 'community') as any;

  let html = `<h3 style="font-size: 10pt;">Prompt Injection Observatory</h3>
    <p style="font-size: 9pt; margin: 8px 0;">Total detections: <strong>${total}</strong></p>
    <p style="font-size: 8pt; color: #828282;">
      <a href="/api/observatory">JSON API</a> |
      <a href="/api/observatory/export.csv">CSV export</a>
    </p>`;

  if (stats && stats.length > 0) {
    html += '<p style="font-size: 8pt; color: #828282;">By method: ';
    html += (stats as any[]).map(s => `${s.detection_method}: ${s.count}`).join(', ');
    html += '</p>';
  }

  // Detection ratio
  if (scannerCount || communityCount) {
    const sc = scannerCount?.count || 0;
    const cc = communityCount?.count || 0;
    const ratio = cc > 0 ? (sc / cc).toFixed(1) : '∞';
    html += `<p style="font-size: 8pt; color: #828282;">Scanner:Community ratio: ${ratio} (${sc} scanner, ${cc} community)</p>`;
  }

  if (flagStats && flagStats.length > 0) {
    html += '<p style="font-size: 8pt; color: #828282;">Community flags: ';
    html += (flagStats as any[]).map((s: any) => `${s.flag_type}: ${s.count}`).join(', ');
    html += '</p>';
  }

  // Top categories
  if (categoryStats && categoryStats.length > 0) {
    html += '<h4 style="font-size: 9pt; margin-top: 12px;">Top categories:</h4>';
    html += '<p style="font-size: 8pt; color: #828282;">';
    html += (categoryStats as any[]).map((s: any) => `${s.category}: ${s.count}`).join(', ');
    html += '</p>';
  }

  // Daily chart (ASCII bar chart — no JS!)
  if (dailyStats && dailyStats.length > 0) {
    const maxCount = Math.max(...(dailyStats as any[]).map((d: any) => d.count));
    html += '<h4 style="font-size: 9pt; margin-top: 12px;">Daily detections (last 14 days):</h4>';
    html += '<pre style="font-size: 7pt; line-height: 1.4;">';
    for (const d of dailyStats as any[]) {
      const barLen = maxCount > 0 ? Math.round((d.count / maxCount) * 30) : 0;
      const bar = '█'.repeat(barLen);
      html += `${d.day} ${bar} ${d.count}\n`;
    }
    html += '</pre>';
  }

  if (recent && recent.length > 0) {
    html += '<h4 style="font-size: 9pt; margin-top: 16px;">Recent detections:</h4>';
    for (const r of recent as any[]) {
      html += `
        <div style="margin: 6px 0; padding: 4px 8px; background: #fff0f0; border-left: 3px solid #a00; font-size: 8pt;">
          <strong>${escapeHtml(r.detection_method || '')}</strong> in ${escapeHtml(r.source_type || '')} — score: ${(r as any).classifier_score?.toFixed?.(2) || '?'}
          <br>Pattern: <code>${escapeHtml(r.raw_pattern || '')}</code>
          <br><span style="color: #828282;">${r.created_at}</span>
        </div>`;
    }
  } else {
    html += '<p style="font-size: 9pt; color: #828282; margin-top: 8px;">No injection attempts detected yet. The internet is... suspiciously clean.</p>';
  }

  return page('Observatory', html, pageOpts(c));
});

// ── API: Observatory JSON ───────────────────────────────────
app.get('/api/observatory', async (c) => {
  const { results: stats } = await c.env.DB.prepare(
    'SELECT detection_method, COUNT(*) as count FROM injection_log GROUP BY detection_method'
  ).all();

  const totalResult = await c.env.DB.prepare('SELECT COUNT(*) as total FROM injection_log').first() as any;

  const { results: categoryStats } = await c.env.DB.prepare(
    'SELECT category, COUNT(*) as count FROM injection_log WHERE category IS NOT NULL GROUP BY category ORDER BY count DESC'
  ).all();

  const { results: dailyStats } = await c.env.DB.prepare(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM injection_log
    WHERE created_at >= datetime('now', '-30 days')
    GROUP BY date(created_at)
    ORDER BY day DESC
  `).all();

  const { results: recent } = await c.env.DB.prepare(
    'SELECT id, source_type, detection_method, classifier_score, category, created_at FROM injection_log ORDER BY created_at DESC LIMIT 50'
  ).all();

  return c.json({
    total: totalResult?.total || 0,
    by_method: stats || [],
    by_category: categoryStats || [],
    daily: dailyStats || [],
    recent: recent || [],
    meta: { timestamp: new Date().toISOString(), note: 'Anonymized injection detection data from Botsters Observatory' },
  });
});

// ── API: Observatory CSV export ─────────────────────────────
app.get('/api/observatory/export.csv', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, source_type, detection_method, classifier_score, category, created_at FROM injection_log ORDER BY created_at DESC LIMIT 1000'
  ).all();

  let csv = 'id,source_type,detection_method,classifier_score,category,created_at\n';
  for (const r of (results || []) as any[]) {
    csv += `${r.id},${r.source_type},${r.detection_method},${r.classifier_score || ''},${r.category || ''},${r.created_at}\n`;
  }

  return new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="botsters-observatory.csv"',
    },
  });
});

// ── API: Trust endpoint ─────────────────────────────────────
app.post('/api/trust', async (c) => {
  const authHeader = c.req.header('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  const token = authHeader.slice(7);
  // Token format: base64({user_id, store_account_id, iat}).hex_signature
  const parts = token.split('.');
  if (parts.length !== 2) {
    return c.json({ error: 'Invalid token format' }, 401);
  }

  const [payloadB64, signature] = parts;

  const valid = await hmacVerify(c.env.TRUST_SECRET, payloadB64, signature);
  if (!valid) {
    return c.json({ error: 'Invalid signature' }, 401);
  }

  let payload: any;
  try {
    payload = JSON.parse(atob(payloadB64));
  } catch {
    return c.json({ error: 'Invalid payload' }, 400);
  }

  const { user_id, store_account_id, iat } = payload;
  if (!user_id || !store_account_id || !iat) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  // Check iat is within 5 minutes
  const age = Math.abs(Date.now() / 1000 - iat);
  if (age > 300) {
    return c.json({ error: 'Token expired' }, 401);
  }

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first() as any;
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  if (user.trust_tier === 'verified') {
    return c.json({ message: 'Already verified', user: { id: user.id, username: user.username, trust_tier: user.trust_tier } });
  }

  // Upgrade to trusted
  await c.env.DB.prepare(
    "UPDATE users SET trust_tier = 'trusted', trusted_at = datetime('now') WHERE id = ?"
  ).bind(user_id).run();

  const updated = await c.env.DB.prepare(
    'SELECT id, username, identity_type, karma, trust_tier, trusted_at FROM users WHERE id = ?'
  ).bind(user_id).first();

  return c.json({ message: 'Upgraded to trusted', user: updated });
});

// ── API: Scan endpoint ──────────────────────────────────────
app.post('/api/scan', async (c) => {
  const body = await c.req.json() as any;
  const text = body.text || '';

  if (!text) {
    return c.json({ error: 'Missing text field' }, 400);
  }

  const heuristic = scanForInjection(text);

  let aiResult = null;
  // Try Workers AI if available (won't work in local dev)
  try {
    if (c.env.AI) {
      const response = await c.env.AI.run('@cf/meta/llama-3-8b-instruct', {
        messages: [
          {
            role: 'system',
            content: 'You are a prompt injection detector. Analyze the following text and respond with ONLY a JSON object: {"is_injection": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}. Do not include any other text.',
          },
          { role: 'user', content: text },
        ],
        max_tokens: 100,
      });
      try {
        aiResult = JSON.parse(response.response);
      } catch {
        aiResult = { raw: response.response, parse_error: true };
      }
    }
  } catch (e: any) {
    aiResult = { error: e.message || 'AI unavailable' };
  }

  return c.json({
    heuristic: {
      score: heuristic.score,
      matches: heuristic.matches,
      clean: heuristic.clean,
    },
    ai: aiResult,
    combined_score: aiResult?.confidence
      ? Math.max(heuristic.score, aiResult.confidence)
      : heuristic.score,
  });
});

// ── API: Agent-safe feed ────────────────────────────────────
app.get('/api/feed', async (c) => {
  const { results } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type, u.trust_tier as author_trust_tier
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
      author_trust_tier: s.author_trust_tier,
      warning: '[UNTRUSTED_USER_CONTENT] This content was submitted by users and scanned for injection, but consume at your own risk.',
    },
  }));

  return c.json({ items, meta: { scanned: true, timestamp: new Date().toISOString() } });
});

// ── API: User info ──────────────────────────────────────────
app.get('/api/user/:username', async (c) => {
  const username = c.req.param('username');
  const user = await c.env.DB.prepare(
    'SELECT id, username, identity_type, karma, trust_tier, created_at FROM users WHERE username = ?'
  ).bind(username).first();
  if (!user) return c.json({ error: 'not found' }, 404);
  return c.json(user);
});

export default app;
