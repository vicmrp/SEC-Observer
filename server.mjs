import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { Store } from './src/store.mjs';
import { WindowsCollector } from './src/collector.mjs';
import { Sessions } from './src/sessions.mjs';
import { evidencePayload, redact } from './src/events.mjs';
import { body, json, HttpError } from './src/http.mjs';
const root = fileURLToPath(new URL('.',import.meta.url));

export async function createApp({ dataDirectory = process.env.OBSERVE_DATA_DIR || path.join(process.env.LOCALAPPDATA || path.join(os.homedir(),'.local','share'),'Observe','sessions'), collector = new WindowsCollector(), analyzer } = {}) {
  const token = randomBytes(32).toString('hex');
  const config = { mode:process.env.OBSERVE_GATEWAY_URL ? 'managed' : 'byok', apiKey:process.env.OPENAI_API_KEY || '', gateway:process.env.OBSERVE_GATEWAY_URL || '', accessToken:process.env.OBSERVE_ACCESS_TOKEN || '' };
  const sessions = new Sessions(new Store(dataDirectory),collector,config,analyzer); await sessions.init();
  let sensorCache = null; let sensorAt = 0;
  const previews = new Map();
  const publicConfig = () => ({ mode:config.mode, hasApiKey:!!config.apiKey, gateway:config.gateway, hasAccessToken:!!config.accessToken, model:'gpt-6-astra', ready:sessions.ready() });
  const server = http.createServer(async (req,res) => {
    const port = server.address().port;
    const hosts = new Set([`127.0.0.1:${port}`,`localhost:${port}`]);
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Frame-Options','DENY'); res.setHeader('Referrer-Policy','no-referrer');
    try {
      if (!hosts.has(req.headers.host)) throw new HttpError(403,'Observe accepts local connections only.');
      if (req.headers.origin && ![`http://127.0.0.1:${port}`,`http://localhost:${port}`].includes(req.headers.origin)) throw new HttpError(403,'Cross-origin requests are not allowed.');
      const url = new URL(req.url,`http://127.0.0.1:${port}`);
      if (url.pathname.startsWith('/api/')) {
        const supplied = Buffer.from(req.headers['x-observe-token'] || ''); const expected = Buffer.from(token);
        if (supplied.length !== expected.length || !timingSafeEqual(supplied,expected)) throw new HttpError(403,'Reload Observe to reconnect securely.');
        if (req.method === 'GET' && url.pathname === '/api/status') {
          if (!sensorCache || Date.now()-sensorAt > 30_000 || url.searchParams.get('refresh') === '1') {
            try { sensorCache = await collector.status(); sensorAt = Date.now(); }
            catch (e) { sensorCache = { channels:[], error:e.message }; }
          }
          return json(res,200,{ sensors:sensorCache, config:publicConfig(), activeId:sessions.activeId, platform:process.platform, storageError:sessions.lastTickError });
        }
        if (req.method === 'GET' && url.pathname === '/api/sessions') return json(res,200,sessions.list());
        if (req.method === 'POST' && url.pathname === '/api/config') {
          if (sessions.activeId || [...sessions.items.values()].some(s => s.analyzing)) throw new HttpError(409,'Finish capture and analysis before changing providers.');
          const input = await body(req);
          if (!['byok','managed'].includes(input.mode)) throw new HttpError(400,'Choose an analysis provider.');
          for (const key of ['apiKey','accessToken','gateway']) if (key in input && (typeof input[key] !== 'string' || input[key].length > 2048)) throw new HttpError(400,'Invalid settings.');
          if (input.gateway) {
            let u; try { u = new URL(input.gateway); } catch { throw new HttpError(400,'Enter a valid service URL.'); }
            if ((u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1','localhost'].includes(u.hostname))) || u.username || u.password || u.search || u.hash) throw new HttpError(400,'Use an HTTPS service URL without credentials or a query string. HTTP localhost is allowed for development.');
          }
          config.mode = input.mode;
          for (const key of ['apiKey','accessToken','gateway']) if (key in input) config[key] = input[key].trim();
          return json(res,200,publicConfig());
        }
        if (req.method === 'POST' && url.pathname === '/api/start') return json(res,201,await sessions.start(await body(req)));
        const match = url.pathname.match(/^\/api\/sessions\/([a-f0-9-]{36})(?:\/(stop|analyze|preview|export))?$/);
        if (match) {
          const [,id,action] = match; const s = sessions.get(id);
          if (req.method === 'GET' && !action) return json(res,200,s);
          if (req.method === 'DELETE' && !action) { await sessions.remove(id); return json(res,200,{deleted:true}); }
          if (req.method === 'POST' && action === 'stop') { await body(req); return json(res,200,await sessions.stop(id)); }
          if (req.method === 'POST' && action === 'analyze') {
            const input = await body(req);
            // Return immediately; the UI polls report state while the provider works.
            if (input.consent !== true || !sessions.ready() || s.analyzing || s.analysisCount >= 10) throw new HttpError(400,'Consent, a configured provider, and an available analysis slot are required.');
            const preview = previews.get(input.previewId);
            if (!preview || preview.sessionId !== id || Date.now()-preview.created > 600_000 || preview.provider !== JSON.stringify(publicConfig())) throw new HttpError(400,'Preview the evidence again; the snapshot expired or the provider changed.');
            previews.delete(input.previewId);
            sessions.runAnalysis(id,true,preview.payload).catch(() => {}); return json(res,202,{accepted:true});
          }
          if (req.method === 'GET' && action === 'preview') {
            for (const [key,value] of previews) if (Date.now()-value.created > 600_000) previews.delete(key);
            if (previews.size >= 20) previews.delete(previews.keys().next().value);
            const previewId = randomBytes(24).toString('hex'), payload = evidencePayload(s);
            previews.set(previewId,{sessionId:id,created:Date.now(),payload,provider:JSON.stringify(publicConfig())});
            return json(res,200,{previewId,payload});
          }
          if (req.method === 'GET' && action === 'export') { res.setHeader('Content-Disposition',`attachment; filename="observe-${id}.json"`); return json(res,200,redact({...s,cursors:undefined})); }
        }
        throw new HttpError(404,'Endpoint not found.');
      }
      if (req.method !== 'GET') throw new HttpError(405,'Method not allowed.');
      const files = { '/':['public/index.html','text/html'], '/app.js':['public/app.js','text/javascript'], '/styles.css':['public/styles.css','text/css'], '/favicon.svg':['public/favicon.svg','image/svg+xml'] };
      const asset = files[url.pathname]; if (!asset) throw new HttpError(404,'Not found.');
      let content = await readFile(path.join(root,asset[0]),'utf8');
      if (url.pathname === '/') content = content.replace('__OBSERVE_TOKEN__',token);
      res.writeHead(200,{'Content-Type':`${asset[1]}; charset=utf-8`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}); res.end(content);
    } catch (error) { if (!res.headersSent) json(res,error.status || 500,{error:error.status ? error.message : 'Observe could not complete this operation. Check local storage and try again.'}); else res.end(); }
  });
  server.requestTimeout = 30_000; server.headersTimeout = 15_000;
  server.on('close',() => sessions.close());
  return { server,sessions,config };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const app = await createApp(); const port = Number(process.env.PORT || 4317);
  app.server.on('error',error => { console.error(error.code === 'EADDRINUSE' ? `Port ${port} is in use. Observe may already be running.` : 'Could not start Observe.'); process.exitCode = 1; });
  app.server.listen(port,'127.0.0.1',() => console.log(`Observe is ready at http://127.0.0.1:${port}\nEvents stay local until you request AI analysis. Ctrl+C stops the app.`));
  let closing = false;
  const shutdown = async () => { if (closing) return; closing = true; app.sessions.close(); if (app.sessions.activeId) await app.sessions.stop(app.sessions.activeId).catch(() => {}); app.server.close(); setTimeout(() => process.exit(0),2000).unref(); };
  process.on('SIGINT',shutdown); process.on('SIGTERM',shutdown);
}
