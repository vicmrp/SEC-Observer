// A single-instance managed-service MVP. Deploy behind an HTTPS reverse proxy.
import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { body, json, HttpError } from './src/http.mjs';
import { openAIAnalysis } from './src/analysis.mjs';

export function validatePayload(p) {
  if (!p || typeof p.question !== 'string' || p.question.length > 2000 || !Array.isArray(p.events) || p.events.length > 350 || !p.coverage || !Array.isArray(p.coverage.warnings) || !p.coverage.warnings.every(x => typeof x === 'string')) throw new HttpError(400,'Invalid evidence payload.');
  if (!p.events.every(e => e && typeof e.id === 'string' && typeof e.timestamp === 'string' && e.data && typeof e.data === 'object' && !Array.isArray(e.data))) throw new HttpError(400,'Invalid event.');
  if (new Set(p.events.map(e => e.id)).size !== p.events.length) throw new HttpError(400,'Duplicate event IDs.');
  for (const key of ['captured','included','omitted','shortenedFields']) if (!Number.isInteger(p.coverage[key]) || p.coverage[key] < 0 || p.coverage[key] > 5000) throw new HttpError(400,'Invalid evidence coverage.');
  if (p.coverage.included !== p.events.length || p.coverage.captured !== p.coverage.included+p.coverage.omitted) throw new HttpError(400,'Inconsistent evidence coverage.');
  return p;
}

export async function createGateway({ key = process.env.OPENAI_API_KEY, tokenHashes = (process.env.OBSERVE_CUSTOMER_TOKEN_HASHES || '').split(',').filter(Boolean), dataDir = process.env.OBSERVE_GATEWAY_DATA || '.data/gateway', dailyLimit = Number(process.env.OBSERVE_DAILY_LIMIT || 20), analyzer = openAIAnalysis } = {}) {
  if (!key || !tokenHashes.length || !tokenHashes.every(t => /^[a-f0-9]{64}$/.test(t)) || !Number.isInteger(dailyLimit) || dailyLimit < 1) throw new Error('Configure OPENAI_API_KEY, SHA-256 customer token hashes, and a positive daily request limit.');
  await mkdir(dataDir,{recursive:true,mode:0o700}); const usageFile = path.join(dataDir,'usage.json');
  let usage; try { usage = JSON.parse(await readFile(usageFile,'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw new Error('Gateway usage ledger is unreadable; refusing to reset quotas.'); usage = {}; }
  let saving = Promise.resolve(); const busy = new Set();
  const reserve = customer => {
    const job = saving.then(async () => {
      const day = new Date().toISOString().slice(0,10), id = `${day}:${customer}`;
      if ((usage[id] || 0) >= dailyLimit) throw new HttpError(429,'Daily request allowance reached.');
      usage[id] = (usage[id] || 0)+1;
      usage = Object.fromEntries(Object.entries(usage).filter(([k]) => k.startsWith(day)));
      await writeFile(`${usageFile}.tmp`,JSON.stringify(usage),{mode:0o600}); await rename(`${usageFile}.tmp`,usageFile);
    }); saving = job.catch(() => {}); return job;
  };
  const server = http.createServer(async (req,res) => {
    let customer;
    try {
      if (req.method !== 'POST' || req.url !== '/v1/analyze') throw new HttpError(404,'Not found.');
      const credential = /^Bearer (.{20,512})$/.exec(req.headers.authorization || '')?.[1];
      if (!credential) throw new HttpError(401,'A valid access token is required.');
      const digest = createHash('sha256').update(credential).digest();
      customer = tokenHashes.find(h => timingSafeEqual(digest,Buffer.from(h,'hex')));
      if (!customer) throw new HttpError(401,'A valid access token is required.');
      if (busy.has(customer)) throw new HttpError(429,'An analysis is already running for this account.');
      if (busy.size >= 4) throw new HttpError(503,'The service is busy. Try again later.');
      const payload = validatePayload(await body(req,220_000));
      // Check again after reading the request body; concurrent requests may have arrived.
      if (busy.has(customer) || busy.size >= 4) throw new HttpError(429,'An analysis slot is not currently available.');
      busy.add(customer);
      try { await reserve(customer); json(res,200,{...await analyzer(payload,key),provider:'managed'}); }
      finally { busy.delete(customer); }
    } catch (e) { json(res,e.status || 500,{error:e.status ? e.message : 'Managed analysis is temporarily unavailable.'}); }
  });
  server.requestTimeout = 30_000; server.headersTimeout = 15_000;
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const server = await createGateway();
  server.listen(Number(process.env.GATEWAY_PORT || 4318),process.env.GATEWAY_HOST || '127.0.0.1',() => console.log('Observe managed gateway started. Use an HTTPS reverse proxy for remote clients.'));
}
