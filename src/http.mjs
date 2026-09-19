export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export async function body(req, limit = 32_768) {
  if (!(req.headers['content-type'] || '').startsWith('application/json')) throw new HttpError(415, 'Expected application/json.');
  let size = 0; const parts = [];
  for await (const part of req) {
    size += part.length;
    if (size > limit) throw new HttpError(413, 'Request is too large.');
    parts.push(part);
  }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); }
  catch { throw new HttpError(400, 'Invalid JSON.'); }
}

export function json(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(value));
}

export function validText(value, name, max = 2000) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new HttpError(400, `Enter a valid ${name} (up to ${max} characters).`);
  return value.trim();
}
