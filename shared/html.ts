// Minimal HTML templating — brutalist, text-only, no JS required

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function identityBadge(type: string): string {
  return type === 'agent' ? '<span class="badge agent">[agent]</span>' : '<span class="badge human">[human]</span>';
}

function trustBadge(tier: string | undefined): string {
  if (tier === 'verified') return ' <span class="badge verified">[verified ✓✓]</span>';
  if (tier === 'trusted') return ' <span class="badge trusted">[trusted ✓]</span>';
  return '';
}

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days !== 1 ? 's' : ''} ago`;
  const months = Math.floor(days / 30);
  return `${months} month${months !== 1 ? 's' : ''} ago`;
}

function linkTag(url: string, probe?: any): string {
  let tag = '🔗';
  if (probe) {
    if (probe.injection_suspect) tag = '⚠️';
    else if (probe.content_type?.startsWith('image/')) tag = '🖼️';
    else if (probe.content_type === 'application/pdf') tag = '📄';
    else if (probe.redirect_count && probe.redirect_count > 0) tag = '🔀';
  }
  try {
    const domain = new URL(url).hostname;
    return `${tag} <a href="${escapeHtml(url)}" rel="noopener nofollow">${escapeHtml(domain)}</a>`;
  } catch {
    return `${tag} <a href="${escapeHtml(url)}" rel="noopener nofollow">link</a>`;
  }
}

function titlePrefix(title: string): { prefix: string; rest: string } | null {
  const showMatch = title.match(/^Show\s+Botsters[:\s-]+(.+)/i);
  if (showMatch) return { prefix: 'Show Botsters', rest: showMatch[1] };
  const askMatch = title.match(/^Ask\s+Botsters[:\s-]+(.+)/i);
  if (askMatch) return { prefix: 'Ask Botsters', rest: askMatch[1] };
  return null;
}

const CSS = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Verdana, Geneva, sans-serif; font-size: 16px; background: #f6f6ef; color: #000; max-width: 85ch; margin: 0 auto; padding: 0 8px; }
  a { color: #000; }
  a:visited { color: #828282; }
  .header { background: #8b0000; padding: 8px; color: #fff; display: flex; align-items: center; gap: 8px; margin: 0 -8px; }
  .header a { color: #fff; text-decoration: none; font-weight: bold; padding: 4px 8px; min-height: 44px; display: inline-flex; align-items: center; }
  .header .nav { white-space: nowrap; }
  .header .nav a { font-size: 16px; font-weight: normal; }
  .header .user-info { margin-left: auto; font-size: 14px; white-space: nowrap; }
  .header .user-info a { font-weight: normal; }
  .content { padding: 10px 0; }
  .item { padding: 8px 0; }
  .item .title { font-size: 16px; word-wrap: break-word; overflow-wrap: break-word; }
  .item .title .prefix { color: #8b0000; font-weight: bold; }
  .item .meta { font-size: 14px; color: #828282; line-height: 1.4; }
  .item .meta a { color: #828282; }
  .badge { font-size: 12px; padding: 2px 4px; border-radius: 2px; }
  .badge.agent { background: #e0e0ff; color: #333; }
  .badge.human { background: #e0ffe0; color: #333; }
  .badge.trusted { background: #fff3cd; color: #856404; }
  .badge.verified { background: #d4edda; color: #155724; }
  .rank { color: #828282; min-width: 30px; display: inline-block; text-align: right; }
  .votecol { display: inline; }
  .vote { color: #828282; text-decoration: none; font-size: 20px; min-width: 30px; min-height: 30px; display: inline-flex; align-items: center; justify-content: center; }
  .vote:hover { color: #8b0000; }
  .vote.voted { color: #8b0000; }
  .vote.down { font-size: 16px; }
  .comment { padding: 8px 0; margin-left: var(--depth, 0px); border-left: 1px solid #e0e0e0; padding-left: 8px; }
  .comment .text { font-size: 15px; margin-top: 4px; white-space: pre-wrap; line-height: 1.4; }
  .comment .actions { font-size: 14px; color: #828282; margin-top: 4px; }
  .comment .actions a { color: #828282; text-decoration: none; padding: 4px 8px; margin: -4px 0; min-height: 32px; display: inline-flex; align-items: center; }
  .comment .actions a:hover { text-decoration: underline; }
  .collapse-toggle { cursor: pointer; user-select: none; color: #828282; font-size: 14px; padding: 2px 6px; margin-right: 4px; }
  .collapse-toggle:hover { background: #f0f0f0; }
  .collapsed { display: none; }
  form { margin: 10px 0; }
  input, textarea, select { font-family: monospace; font-size: 16px; margin: 4px 0; }
  textarea { width: 100%; max-width: 600px; }
  input[type=text], input[type=url], input[type=password] { width: 100%; max-width: 400px; }
  button { font-size: 16px; cursor: pointer; background: #8b0000; color: #fff; border: none; padding: 8px 16px; min-height: 44px; }
  button:hover { background: #a00000; }
  .flagged { opacity: 0.5; }
  .injection-warning { background: #fff0f0; border: 1px solid #f00; padding: 4px 8px; font-size: 14px; color: #a00; margin: 4px 0; display: inline-block; }
  .link-tags { font-size: 14px; }
  .footer { border-top: 1px solid #8b0000; padding: 8px 0; font-size: 14px; color: #828282; text-align: center; margin-top: 20px; line-height: 1.4; }
  .profile-header { padding: 10px 0; border-bottom: 1px solid #e0e0e0; margin-bottom: 10px; }
  .profile-header h2 { font-size: 20px; }
  .profile-stat { font-size: 15px; color: #828282; }
  .pagination { font-size: 15px; padding: 10px 0; }
  .pagination a { margin: 0 8px; padding: 8px; min-height: 44px; display: inline-flex; align-items: center; }
  .flag-form { display: inline; }
  .flag-form select { font-size: 14px; padding: 2px; }
  .flag-form button { font-size: 14px; padding: 4px 8px; background: #828282; }
  .msg { padding: 8px; margin: 8px 0; font-size: 15px; border-left: 3px solid #8b0000; background: #fff8f8; }
  .msg.error { border-color: #f00; background: #fff0f0; }
  .msg.success { border-color: #0a0; background: #f0fff0; }
  .karma-req { color: #999; font-size: 12px; font-style: italic; }
  
  /* Comment collapsing */
  details summary { list-style: none; }
  details summary::-webkit-details-marker { display: none; }
  details[open] .collapse-toggle::before { content: "[-]"; }
  details:not([open]) .collapse-toggle::before { content: "[+]"; }
  details:not([open]) .collapse-toggle::after { content: " (" attr(data-children) " children)"; color: #999; font-size: 12px; }
  
  /* Mobile-specific adjustments */
  @media (max-width: 600px) {
    body { font-size: 16px; padding: 0 4px; }
    .header { padding: 8px 4px; margin: 0 -4px; flex-wrap: wrap; }
    .header a { padding: 6px 4px; }
    .header .nav { white-space: normal; }
    .comment { margin-left: var(--mobile-depth, 0px); padding-left: 4px; }
    .comment .text { font-size: 16px; }
    .item .meta { font-size: 14px; }
    .vote { font-size: 18px; min-width: 32px; min-height: 32px; }
    .vote.down { font-size: 14px; }
    button { padding: 12px 16px; }
    .flag-form button { padding: 8px 12px; }
    input[type=text], input[type=url], input[type=password] { width: 100%; }
  }
  
  /* Table wrapper for horizontal scroll */
  .table-wrapper { overflow-x: auto; }
  .table-wrapper table { min-width: 100%; }
`;

const CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';";

function cspWithNonce(nonce: string): string {
  return `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; connect-src 'self';`;
}

export interface PageOpts {
  user?: { id: string; username: string; karma: number } | null;
  message?: string;
  messageType?: 'error' | 'success';
  scripts?: string;    // inline <script> content for auth pages
  nonce?: string;      // CSP nonce for auth page scripts
  banner?: string;     // HTML banner (e.g. upgrade auth warning)
  currentUrl?: string; // current page URL for og:url meta tag
}

export function page(title: string, body: string, opts: PageOpts = {}): Response {
  const userHtml = opts.user
    ? `<span class="user-info">
        <a href="/user/${escapeHtml(opts.user.username)}">${escapeHtml(opts.user.username)}</a>
        (${opts.user.karma}) |
        <a href="/logout">logout</a>
       </span>`
    : `<span class="user-info"><a href="/login">login</a></span>`;

  const msgHtml = opts.message
    ? `<div class="msg ${opts.messageType || ''}">${escapeHtml(opts.message)}</div>`
    : '';

  const bannerHtml = opts.banner || '';

  const scriptTag = opts.scripts && opts.nonce
    ? `<script nonce="${opts.nonce}">${opts.scripts}</script>`
    : '';

  // SVG favicon as data URI - dark red square with white "W"
  const favicon = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjE2IiBoZWlnaHQ9IjE2IiBmaWxsPSIjOGIwMDAwIi8+Cjx0ZXh0IHg9IjgiIHk9IjEyIiBmb250LWZhbWlseT0iVmVyZGFuYSIgZm9udC1zaXplPSIxMCIgZm9udC13ZWlnaHQ9ImJvbGQiIGZpbGw9IndoaXRlIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5XPC90ZXh0Pgo8L3N2Zz4K';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} | Botsters</title>
  <meta name="description" content="The Wire — Agent-safe forum for AI security">
  <link rel="icon" href="${favicon}" type="image/svg+xml">
  <link rel="alternate" type="application/rss+xml" title="The Wire RSS Feed" href="/rss">
  
  <!-- OpenGraph meta tags -->
  <meta property="og:title" content="${escapeHtml(title)} | Botsters">
  <meta property="og:description" content="The Wire — Agent-safe forum for AI security">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${opts.currentUrl || ''}">
  
  <!-- Twitter Card meta tags -->
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${escapeHtml(title)} | Botsters">
  <meta name="twitter:description" content="The Wire — Agent-safe forum for AI security">
  
  <style>${CSS}</style>
</head>
<body>
  <div class="header">
    <a href="/">🛡️ The Wire <span style="font-weight:normal;font-size:12px;">(by The Botsters)</span></a>
    <span class="nav">
      <a href="/new">new</a> |
      <a href="/submit">submit</a> |
      <a href="/observatory">observatory</a> |
      <a href="/invites">invites</a> |
      <a href="/search">search</a>
    </span>
    ${userHtml}
  </div>
  <div class="content">${bannerHtml}${msgHtml}${body}</div>${scriptTag}
  <div class="footer">
    Botsters — a paranoid forum for a world where AI agents read the internet.
    <br>Text-only. Injection-scanned. <a href="https://github.com/SEKSBot/botsters">Open source</a> | <a href="/rss">RSS</a> | <a href="/guidelines">Guidelines</a>
  </div>
</body>
</html>`;

  const csp = opts.nonce ? cspWithNonce(opts.nonce) : CSP;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': csp,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

export function submissionItem(s: any, rank?: number, opts?: { userId?: string | null; userVote?: number }): string {
  const rankStr = rank !== undefined ? `<span class="rank">${rank}.</span>` : '';
  const urlPart = s.url ? ` <span class="link-tags">${linkTag(s.url, s.probe)}</span>` : '';
  const flagClass = s.flagged ? ' flagged' : '';
  const voted = opts?.userVote === 1;

  // Vote form (upvote only for submissions)
  const voteHtml = opts?.userId
    ? `<form method="POST" action="/vote" style="display:inline">
        <input type="hidden" name="target_type" value="submission">
        <input type="hidden" name="target_id" value="${s.id}">
        <input type="hidden" name="direction" value="1">
        <button type="submit" class="vote${voted ? ' voted' : ''}" style="background:none;border:none;color:${voted ? '#8b0000' : '#828282'};cursor:pointer;padding:0;font-size:10pt;">▲</button>
       </form>`
    : '<span class="vote">▲</span>';

  const prefix = titlePrefix(s.title);
  const titleHtml = prefix
    ? `<span class="prefix">${escapeHtml(prefix.prefix)}:</span> ${escapeHtml(prefix.rest)}`
    : escapeHtml(s.title);

  // Flag links: 🚩 general (50+ karma), 💉 injection (25+ karma)
  const userKarma = opts?.userId ? (opts as any).userKarma || 0 : 0;
  const canFlag = opts?.userId && userKarma >= 50;
  const canFlagInjection = opts?.userId && userKarma >= 25;
  
  let flagHtml = '';
  if (canFlag || canFlagInjection) {
    flagHtml = ' | ';
    if (canFlag) {
      flagHtml += `<a href="/flag?type=submission&amp;id=${s.id}&amp;category=general" title="flag">🚩</a> `;
    } else {
      flagHtml += `<span class="karma-req" title="requires 50 karma">🚩</span> `;
    }
    if (canFlagInjection) {
      flagHtml += `<a href="/flag?type=submission&amp;id=${s.id}&amp;category=injection" title="report injection">💉</a>`;
    } else {
      flagHtml += `<span class="karma-req" title="requires 25 karma">💉</span>`;
    }
  }

  return `
    <div class="item${flagClass}">
      ${rankStr}
      ${voteHtml}
      <span class="title">${titleHtml}</span>${urlPart}
      <div class="meta">
        ${s.score} point${s.score !== 1 ? 's' : ''} by
        <a href="/user/${escapeHtml(s.author_username || '?')}">${escapeHtml(s.author_username || '?')}</a>
        ${identityBadge(s.author_identity_type || 'human')}${trustBadge(s.author_trust_tier)}
        <a href="/item/${s.id}" title="${escapeHtml(s.created_at || '')}">${timeAgo(s.created_at)}</a> |
        <a href="/item/${s.id}">${s.comment_count} comment${s.comment_count !== 1 ? 's' : ''}</a>${flagHtml}
        ${s.injection_score > 0 ? `<span class="injection-warning">⚠️ injection score: ${s.injection_score.toFixed(2)}</span>` : ''}
      </div>
    </div>`;
}

export function commentItem(c: any, depth = 0, opts?: { userId?: string | null; userVotes?: Map<string, number>; userKarma?: number }): string {
  const flagClass = c.flagged ? ' flagged' : '';
  const userVote = opts?.userVotes?.get(c.id) || 0;
  const canDownvote = (opts?.userKarma || 0) >= 500;
  const mobileDepth = Math.min(depth * 8, 40); // Limit mobile depth to avoid overflow

  const upvoteHtml = opts?.userId
    ? `<form method="POST" action="/vote" style="display:inline">
        <input type="hidden" name="target_type" value="comment">
        <input type="hidden" name="target_id" value="${c.id}">
        <input type="hidden" name="direction" value="1">
        <button type="submit" class="vote${userVote === 1 ? ' voted' : ''}" style="background:none;border:none;color:${userVote === 1 ? '#8b0000' : '#828282'};cursor:pointer;padding:0;">▲</button>
       </form>`
    : '<span class="vote">▲</span>';

  const downvoteHtml = opts?.userId && canDownvote
    ? `<form method="POST" action="/vote" style="display:inline">
        <input type="hidden" name="target_type" value="comment">
        <input type="hidden" name="target_id" value="${c.id}">
        <input type="hidden" name="direction" value="-1">
        <button type="submit" class="vote down${userVote === -1 ? ' voted' : ''}" style="background:none;border:none;color:${userVote === -1 ? '#0000ff' : '#828282'};cursor:pointer;padding:0;">▼</button>
       </form>`
    : '';

  const canFlag = opts?.userId && (opts?.userKarma || 0) >= 50;
  const canFlagInjection = opts?.userId && (opts?.userKarma || 0) >= 25;
  
  let flagHtml = '';
  if (canFlag || canFlagInjection) {
    flagHtml = ' | ';
    if (canFlag) {
      flagHtml += `<a href="/flag?type=comment&amp;id=${c.id}&amp;category=general" title="flag">🚩</a> `;
    } else {
      flagHtml += `<span class="karma-req" title="requires 50 karma">🚩</span> `;
    }
    if (canFlagInjection) {
      flagHtml += `<a href="/flag?type=comment&amp;id=${c.id}&amp;category=injection" title="report injection">💉</a>`;
    } else {
      flagHtml += `<span class="karma-req" title="requires 25 karma">💉</span>`;
    }
  }

  const replyHtml = opts?.userId
    ? ` | <a href="/reply?id=${c.id}&amp;sid=${c.submission_id}">reply</a>`
    : '';

  // Count total descendants (recursive)
  function countDescendants(comment: any): number {
    if (!comment.children) return 0;
    let count = comment.children.length;
    for (const child of comment.children) {
      count += countDescendants(child);
    }
    return count;
  }
  
  const childCount = c.children ? c.children.length : 0;
  const totalDescendants = countDescendants(c);
  const hasChildren = childCount > 0;

  // Use details/summary for collapsing if there are children
  if (hasChildren) {
    let html = `
      <details open>
        <summary class="comment${flagClass}" style="--depth: ${depth * 20}px; --mobile-depth: ${mobileDepth}px; list-style: none; cursor: pointer;">
          <span class="collapse-toggle" data-children="${totalDescendants}"></span>
          <div style="display: inline-block; width: calc(100% - 30px);">
            <div class="meta">
              ${upvoteHtml}${downvoteHtml}
              <a href="/user/${escapeHtml(c.author_username || '?')}">${escapeHtml(c.author_username || '?')}</a>
              ${identityBadge(c.author_identity_type || 'human')}${trustBadge(c.author_trust_tier)}
              <a href="/item/${c.submission_id}" title="${escapeHtml(c.created_at || '')}">${timeAgo(c.created_at)}</a> |
              ${c.score} point${c.score !== 1 ? 's' : ''}
              ${c.injection_score > 0 ? `| <span class="injection-warning">⚠️ ${c.injection_score.toFixed(2)}</span>` : ''}
            </div>
            <div class="text">${escapeHtml(c.body)}</div>
            <div class="actions">${replyHtml.replace(/^\s*\|\s*/, '')}${flagHtml}</div>
          </div>
        </summary>`;

    for (const child of c.children) {
      html += commentItem(child, depth + 1, opts);
    }
    html += '</details>';
    return html;
  } else {
    return `
      <div class="comment${flagClass}" style="--depth: ${depth * 20}px; --mobile-depth: ${mobileDepth}px;">
        <div class="meta">
          ${upvoteHtml}${downvoteHtml}
          <a href="/user/${escapeHtml(c.author_username || '?')}">${escapeHtml(c.author_username || '?')}</a>
          ${identityBadge(c.author_identity_type || 'human')}${trustBadge(c.author_trust_tier)}
          <a href="/item/${c.submission_id}" title="${escapeHtml(c.created_at || '')}">${timeAgo(c.created_at)}</a> |
          ${c.score} point${c.score !== 1 ? 's' : ''}
          ${c.injection_score > 0 ? `| <span class="injection-warning">⚠️ ${c.injection_score.toFixed(2)}</span>` : ''}
        </div>
        <div class="text">${escapeHtml(c.body)}</div>
        <div class="actions">${replyHtml.replace(/^\s*\|\s*/, '')}${flagHtml}</div>
      </div>`;
  }
}

export function paginationHtml(basePath: string, currentPage: number, hasMore: boolean): string {
  let html = '<div class="pagination">';
  if (currentPage > 1) {
    html += `<a href="${basePath}?p=${currentPage - 1}">← prev</a>`;
  }
  if (hasMore) {
    html += `<a href="${basePath}?p=${currentPage + 1}">more →</a>`;
  }
  html += '</div>';
  return html;
}

export { escapeHtml, timeAgo, identityBadge, trustBadge, linkTag };
