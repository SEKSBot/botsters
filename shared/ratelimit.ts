// In-app rate limiting via D1

export async function checkRateLimit(
  db: D1Database,
  key: string,
  windowSeconds: number,
  maxCount: number
): Promise<{ allowed: boolean; remaining: number }> {
  const now = Math.floor(Date.now() / 1000);
  const window = Math.floor(now / windowSeconds);

  // Clean up old windows (older than 1 hour)
  const cutoff = Math.floor((now - 3600) / windowSeconds);
  await db.prepare('DELETE FROM rate_limits WHERE window < ?').bind(cutoff).run();

  // Upsert counter
  const row = await db.prepare(
    'SELECT count FROM rate_limits WHERE key = ? AND window = ?'
  ).bind(key, window).first() as any;

  const currentCount = row?.count || 0;

  if (currentCount >= maxCount) {
    return { allowed: false, remaining: 0 };
  }

  await db.prepare(
    'INSERT INTO rate_limits (key, window, count) VALUES (?, ?, 1) ON CONFLICT(key, window) DO UPDATE SET count = count + 1'
  ).bind(key, window).run();

  return { allowed: true, remaining: maxCount - currentCount - 1 };
}

export function rateLimitResponse(windowSeconds: number): Response {
  return new Response(JSON.stringify({ error: 'Too many requests' }), {
    status: 429,
    headers: {
      'Content-Type': 'application/json',
      'Retry-After': String(windowSeconds),
    },
  });
}
