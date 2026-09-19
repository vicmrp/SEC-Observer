import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { createApp } from '../server.mjs';
import { createGateway } from '../gateway.mjs';
import { evidencePayload } from '../src/events.mjs';

async function appFixture(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(),'observe-http-')); let analyzed;
  const app = await createApp({dataDirectory:dir,collector:{status:async()=>({channels:[]}),collect:async()=>({channels:[]})},analyzer:async p => {analyzed=p;return {provider:'openai',verdict:'review',summary:'Test',findings:[],limitations:[],nextSteps:[]};}});
  await new Promise(resolve => app.server.listen(0,'127.0.0.1',resolve)); const url=`http://127.0.0.1:${app.server.address().port}`;
  const html = await (await fetch(url)).text(); const token = /name="observe-token" content="([a-f0-9]+)"/.exec(html)[1];
  const request = (route,method='GET',data,headers={}) => fetch(url+route,{method,headers:{'X-Observe-Token':token,'Content-Type':'application/json',...headers},...(data !== undefined ? {body:JSON.stringify(data)} : {})});
  t.after(async()=>{app.sessions.close();app.server.closeAllConnections();await new Promise(r=>app.server.close(r));await app.sessions.store.queue;await rm(dir,{recursive:true,force:true});});
  return {app,url,request,getAnalyzed:()=>analyzed};
}
test('localhost API rejects unauthenticated and cross-origin requests',async t=>{const {url,request}=await appFixture(t); assert.equal((await fetch(url+'/api/sessions')).status,403);assert.equal((await request('/api/sessions','GET',undefined,{Origin:'https://evil.example'})).status,403);const hostStatus = await new Promise((resolve,reject)=>{const req=http.get(url,{headers:{Host:'evil.example'}},res=>{res.resume();resolve(res.statusCode);});req.on('error',reject);});assert.equal(hostStatus,403);assert.equal((await request('/api/sessions')).status,200);});
test('UI has restrictive security headers and escaped token bootstrap',async t=>{const {url}=await appFixture(t);const r=await fetch(url);assert.match(r.headers.get('content-security-policy'),/frame-ancestors 'none'/);assert.equal(r.headers.get('cache-control'),'no-store');assert.ok(!(await r.text()).includes('__OBSERVE_TOKEN__'));});
test('settings never return secrets and require secure remote gateway URLs',async t=>{const {request}=await appFixture(t); const r=await request('/api/config','POST',{mode:'byok',apiKey:'sk-test-secret'});assert.equal(r.status,200);assert.ok(!JSON.stringify(await r.json()).includes('sk-test-secret'));assert.equal((await request('/api/config','POST',{mode:'managed',gateway:'http://example.com'})).status,400);});
test('preview analysis sends the exact approved snapshot, not later arrivals',async t=>{
  const {request,app,getAnalyzed}=await appFixture(t);await request('/api/config','POST',{mode:'byok',apiKey:'sk-test'});
  const s=await (await request('/api/start','POST',{question:'Demo',demo:true})).json();
  const preview=await (await request(`/api/sessions/${s.id}/preview`)).json();
  app.sessions.get(s.id).events.push({...s.events[0],id:'new:123',recordId:'123'});
  assert.equal((await request(`/api/sessions/${s.id}/analyze`,'POST',{consent:true,previewId:preview.previewId})).status,202);
  assert.equal(getAnalyzed().events.length,8);assert.equal(getAnalyzed().events.some(e=>e.id==='new:123'),false);
  assert.equal((await request(`/api/sessions/${s.id}/analyze`,'POST',{consent:true,previewId:preview.previewId})).status,400);
});
test('API does not accept unbounded or malformed requests',async t=>{const {request}=await appFixture(t);assert.equal((await request('/api/start','POST',{question:'x'.repeat(40_000)})).status,413);assert.equal((await request('/api/start','POST',{question:'Valid',duration:-1})).status,400);});
test('managed gateway authenticates, persists quotas across restart, and holds server key',async t=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'observe-gateway-'));const credential='customer-token-very-long-random';const hash=createHash('sha256').update(credential).digest('hex');let calls=0;
  const options={key:'server-secret',tokenHashes:[hash],dataDir:dir,dailyLimit:1,analyzer:async(p,key)=>{assert.equal(key,'server-secret');calls++;return {summary:'Okay',verdict:'review',findings:[],limitations:[],nextSteps:[]};}};
  let server=await createGateway(options);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const payload=evidencePayload({question:'Test',focus:'',events:[],warnings:[],sensors:[],start:'2026-01-01',demo:false});
  const call=(token=credential)=>fetch(`http://127.0.0.1:${server.address().port}/v1/analyze`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(payload)});
  assert.equal((await call('invalid-token-with-length')).status,401);assert.equal((await call()).status,200);assert.equal((await call()).status,429);assert.equal(calls,1);
  server.closeAllConnections();await new Promise(r=>server.close(r));server=await createGateway(options);await new Promise(r=>server.listen(0,'127.0.0.1',r));assert.equal((await call()).status,429);
  server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true});
});
