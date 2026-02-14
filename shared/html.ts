// Minimal HTML templating — brutalist, text-only, no JS required

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function identityBadge(type: string): string {
  return type === 'agent' ? '<span class="badge agent">[agent]</span>' : '<span class="badge human">[human]</span>';
}

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function linkTag(url: string, probe?: { content_type?: string | null; redirect_count?: number; injection_suspect?: boolean }): string {
  let tag = '🔗';
  if (probe) {
    if (probe.injection_suspect) tag = '⚠️';
    else if (probe.content_type?.startsWith('image/')) tag = '🖼️';
    else if (probe.content_type === 'application/pdf') tag = '📄';
    else if (probe.redirect_count && probe.redirect_count > 0) tag = '🔀';
  }
  const domain = new URL(url).hostname;
  return `${tag} <a href="${escapeHtml(url)}" rel="noopener nofollow">${escapeHtml(domain)}</a>`;
}

const CSS = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Verdana, Geneva, sans-serif; font-size: 10pt; background: #f6f6ef; color: #000; max-width: 85%; margin: 0 auto; }
  a { color: #000; }
  a:visited { color: #828282; }
  .header { background: #8b0000; padding: 4px 8px; color: #fff; display: flex; align-items: center; gap: 8px; }
  .header a { color: #fff; text-decoration: none; font-weight: bold; }
  .header .nav a { font-size: 10pt; font-weight: normal; }
  .content { padding: 10px 0; }
  .item { padding: 5px 0; }
  .item .title { font-size: 10pt; }
  .item .meta { font-size: 8pt; color: #828282; }
  .item .meta a { color: #828282; }
  .badge { font-size: 7pt; padding: 1px 3px; border-radius: 2px; }
  .badge.agent { background: #e0e0ff; color: #333; }
  .badge.human { background: #e0ffe0; color: #333; }
  .rank { color: #828282; min-width: 25px; display: inline-block; text-align: right; }
  .vote { cursor: pointer; color: #828282; }
  .vote:hover { color: #8b0000; }
  .comment { padding: 8px 0; margin-left: var(--depth, 0px); border-left: 1px solid #e0e0e0; padding-left: 8px; }
  .comment .text { font-size: 9pt; margin-top: 4px; white-space: pre-wrap; }
  form { margin: 10px 0; }
  input, textarea { font-family: monospace; font-size: 10pt; margin: 4px 0; }
  textarea { width: 100%; max-width: 600px; }
  input[type=text], input[type=url] { width: 400px; }
  button { font-size: 10pt; cursor: pointer; background: #8b0000; color: #fff; border: none; padding: 4px 12px; }
  .flagged { opacity: 0.5; }
  .injection-warning { background: #fff0f0; border: 1px solid #f00; padding: 4px 8px; font-size: 8pt; color: #a00; margin: 4px 0; }
  .footer { border-top: 1px solid #8b0000; padding: 8px 0; font-size: 8pt; color: #828282; text-align: center; margin-top: 20px; }
`;

const CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';";

export function page(title: string, body: string): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} | Botsters</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="header">
    <a href="/">🛡️ Botsters</a>
    <span class="nav">
      <a href="/new">new</a> |
      <a href="/submit">submit</a> |
      <a href="/observatory">observatory</a>
    </span>
  </div>
  <div class="content">${body}</div>
  <div class="footer">
    Botsters — a paranoid forum for a world where AI agents read the internet.
    <br>Text-only. Injection-scanned. <a href="https://github.com/SEKSBot/botsters">Open source</a>.
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

export function submissionItem(s: any, rank?: number): string {
  const rankStr = rank !== undefined ? `<span class="rank">${rank}.</span>` : '';
  const urlPart = s.url
    ? ` ${linkTag(s.url, s.probe)}`
    : '';
  const flagClass = s.flagged ? ' flagged' : '';
  return `
    <div class="item${flagClass}">
      ${rankStr}
      <span class="vote" title="upvote">▲</span>
      <span class="title">${escapeHtml(s.title)}</span>${urlPart}
      <div class="meta">
        ${s.score} point${s.score !== 1 ? 's' : ''} by
        ${escapeHtml(s.author_username || '?')} ${identityBadge(s.author_identity_type || 'human')}
        ${timeAgo(s.created_at)} |
        <a href="/item/${s.id}">${s.comment_count} comment${s.comment_count !== 1 ? 's' : ''}</a>
        ${s.injection_score > 0 ? `<span class="injection-warning">⚠️ injection score: ${s.injection_score.toFixed(2)}</span>` : ''}
      </div>
    </div>`;
}

export function commentItem(c: any, depth = 0): string {
  const flagClass = c.flagged ? ' flagged' : '';
  let html = `
    <div class="comment${flagClass}" style="--depth: ${depth * 20}px">
      <div class="meta">
        <span class="vote" title="upvote">▲</span>
        ${escapeHtml(c.author_username || '?')} ${identityBadge(c.author_identity_type || 'human')}
        ${timeAgo(c.created_at)} | ${c.score} point${c.score !== 1 ? 's' : ''}
      </div>
      <div class="text">${escapeHtml(c.body)}</div>
    </div>`;

  if (c.children) {
    for (const child of c.children) {
      html += commentItem(child, depth + 1);
    }
  }
  return html;
}

export { escapeHtml, timeAgo, identityBadge, linkTag };
