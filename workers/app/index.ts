import { Hono } from 'hono';
import { nanoid } from '../../shared/nanoid';
import { scanForInjection } from '../../shared/scanner';
import { rankScore } from '../../shared/ranking';
import { page, submissionItem, commentItem, escapeHtml } from '../../shared/html';

interface Env {
  DB: D1Database;
  ENVIRONMENT: string;
}

const app = new Hono<{ Bindings: Env }>();

// ── Front page ──────────────────────────────────────────────
app.get('/', async (c) => {
  const { results } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0
    ORDER BY s.created_at DESC
    LIMIT 30
  `).all();

  // Sort by HN ranking algorithm
  const ranked = (results || [])
    .map((s: any) => ({ ...s, rank: rankScore(s.score, s.created_at) }))
    .sort((a: any, b: any) => b.rank - a.rank);

  const items = ranked.map((s: any, i: number) => submissionItem(s, i + 1)).join('');
  return page('Front Page', items || '<p>Nothing here yet. <a href="/submit">Submit something.</a></p>');
});

// ── New (chronological) ─────────────────────────────────────
app.get('/new', async (c) => {
  const { results } = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.flagged = 0
    ORDER BY s.created_at DESC
    LIMIT 30
  `).all();

  const items = (results || []).map((s: any, i: number) => submissionItem(s, i + 1)).join('');
  return page('New', items || '<p>Nothing here yet.</p>');
});

// ── Single submission + comments ────────────────────────────
app.get('/item/:id', async (c) => {
  const id = c.req.param('id');

  const submission = await c.env.DB.prepare(`
    SELECT s.*, u.username as author_username, u.identity_type as author_identity_type
    FROM submissions s
    JOIN users u ON s.author_id = u.id
    WHERE s.id = ?
  `).bind(id).first();

  if (!submission) return page('Not Found', '<p>No such item.</p>');

  const { results: comments } = await c.env.DB.prepare(`
    SELECT c.*, u.username as author_username, u.identity_type as author_identity_type
    FROM comments c
    JOIN users u ON c.author_id = u.id
    WHERE c.submission_id = ?
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

  const s = submission as any;
  const bodyHtml = s.body ? `<div style="margin: 10px 0; font-size: 9pt; white-space: pre-wrap;">${escapeHtml(s.body)}</div>` : '';
  const commentsHtml = roots.map((c: any) => commentItem(c)).join('');

  const commentForm = `
    <form method="POST" action="/item/${id}/comment" style="margin-top: 16px;">
      <textarea name="body" rows="4" cols="60" placeholder="Add a comment..." required></textarea><br>
      <input type="hidden" name="author_id" value="demo">
      <button type="submit">add comment</button>
    </form>`;

  return page(s.title,
    submissionItem(s) + bodyHtml + '<hr style="margin: 10px 0; border: none; border-top: 1px solid #e0e0e0;">' +
    commentsHtml + commentForm
  );
});

// ── Submit page ─────────────────────────────────────────────
app.get('/submit', (c) => {
  const form = `
    <h3 style="font-size: 10pt; margin-bottom: 8px;">Submit</h3>
    <form method="POST" action="/submit">
      <label>title: <input type="text" name="title" required maxlength="200"></label><br>
      <label>url: <input type="url" name="url" placeholder="https://..."></label><br>
      <label>or text:</label><br>
      <textarea name="body" rows="6" cols="60"></textarea><br>
      <input type="hidden" name="author_id" value="demo">
      <button type="submit">submit</button>
    </form>
    <p style="font-size: 8pt; color: #828282; margin-top: 8px;">
      Leave url blank to submit a text post (Ask, Show, etc.).<br>
      All submissions are scanned for prompt injection before posting.
    </p>`;
  return page('Submit', form);
});

// ── Handle submission ───────────────────────────────────────
app.post('/submit', async (c) => {
  const body = await c.req.parseBody();
  const title = (body.title as string || '').trim();
  const url = (body.url as string || '').trim() || null;
  const text = (body.body as string || '').trim() || null;
  const authorId = body.author_id as string || 'demo';

  if (!title) return page('Error', '<p>Title is required.</p>');

  // Scan for injection
  const titleScan = scanForInjection(title);
  const textScan = text ? scanForInjection(text) : { score: 0, matches: [], clean: true };
  const injectionScore = Math.max(titleScan.score, textScan.score);

  // Ensure demo user exists
  await c.env.DB.prepare(`
    INSERT OR IGNORE INTO users (id, username, identity_type) VALUES ('demo', 'demo', 'human')
  `).run();

  const id = nanoid();
  await c.env.DB.prepare(`
    INSERT INTO submissions (id, author_id, title, url, body, score, comment_count, injection_score, flagged)
    VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
  `).bind(id, authorId, title, url, text, injectionScore, injectionScore >= 0.7 ? 1 : 0).run();

  // Log injection if detected
  if (!titleScan.clean || !textScan.clean) {
    const allMatches = [...titleScan.matches, ...textScan.matches];
    await c.env.DB.prepare(`
      INSERT INTO injection_log (id, source_type, raw_pattern, detection_method, classifier_score, category)
      VALUES (?, 'submission', ?, 'heuristic', ?, 'unknown')
    `).bind(nanoid(), allMatches.join('; '), injectionScore).run();
  }

  return c.redirect(`/item/${id}`);
});

// ── Handle comment ──────────────────────────────────────────
app.post('/item/:id/comment', async (c) => {
  const submissionId = c.req.param('id');
  const body = await c.req.parseBody();
  const text = (body.body as string || '').trim();
  const authorId = body.author_id as string || 'demo';
  const parentId = (body.parent_id as string || '').trim() || null;

  if (!text) return c.redirect(`/item/${submissionId}`);

  const scan = scanForInjection(text);

  await c.env.DB.prepare(`
    INSERT OR IGNORE INTO users (id, username, identity_type) VALUES ('demo', 'demo', 'human')
  `).run();

  const id = nanoid();
  await c.env.DB.prepare(`
    INSERT INTO comments (id, submission_id, parent_id, author_id, body, score, injection_score, flagged)
    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
  `).bind(id, submissionId, parentId, authorId, text, scan.score, scan.score >= 0.7 ? 1 : 0).run();

  // Update comment count
  await c.env.DB.prepare(`
    UPDATE submissions SET comment_count = comment_count + 1 WHERE id = ?
  `).bind(submissionId).run();

  // Log injection
  if (!scan.clean) {
    await c.env.DB.prepare(`
      INSERT INTO injection_log (id, source_type, raw_pattern, detection_method, classifier_score, category)
      VALUES (?, 'comment', ?, 'heuristic', ?, 'unknown')
    `).bind(nanoid(), scan.matches.join('; '), scan.score).run();
  }

  return c.redirect(`/item/${submissionId}`);
});

// ── Observatory ─────────────────────────────────────────────
app.get('/observatory', async (c) => {
  const { results: recent } = await c.env.DB.prepare(`
    SELECT * FROM injection_log ORDER BY created_at DESC LIMIT 20
  `).all();

  const { results: stats } = await c.env.DB.prepare(`
    SELECT detection_method, COUNT(*) as count FROM injection_log GROUP BY detection_method
  `).all();

  const totalResult = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM injection_log`).first();
  const total = (totalResult as any)?.total || 0;

  let statsHtml = `<h3 style="font-size: 10pt;">Prompt Injection Observatory</h3>
    <p style="font-size: 9pt; margin: 8px 0;">Total detected: <strong>${total}</strong></p>`;

  if (stats && stats.length > 0) {
    statsHtml += '<p style="font-size: 8pt; color: #828282;">By detection method: ';
    statsHtml += (stats as any[]).map(s => `${s.detection_method}: ${s.count}`).join(', ');
    statsHtml += '</p>';
  }

  if (recent && recent.length > 0) {
    statsHtml += '<h4 style="font-size: 9pt; margin-top: 16px;">Recent detections:</h4>';
    for (const r of recent as any[]) {
      statsHtml += `
        <div style="margin: 6px 0; padding: 4px 8px; background: #fff0f0; border-left: 3px solid #a00; font-size: 8pt;">
          <strong>${r.detection_method}</strong> in ${r.source_type} — score: ${r.classifier_score?.toFixed(2) || '?'}
          <br>Pattern: <code>${escapeHtml(r.raw_pattern || '')}</code>
          <br><span style="color: #828282;">${r.created_at}</span>
        </div>`;
    }
  } else {
    statsHtml += '<p style="font-size: 9pt; color: #828282; margin-top: 8px;">No injection attempts detected yet. The internet is... suspiciously clean.</p>';
  }

  return page('Observatory', statsHtml);
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

export default app;
