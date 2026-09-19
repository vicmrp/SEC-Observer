import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../src/store.mjs';
import { Sessions, MAX_EVENTS } from '../src/sessions.mjs';
import { channels } from '../src/collector.mjs';
const raw = id => ({channel:channels[0],recordId:String(id),eventId:1,timestamp:'2026-01-01T00:00:00.000Z',data:{Image:'test.exe'}});
async function create(t, pages=[]) {
  const dir = await mkdtemp(path.join(os.tmpdir(),'observe-test-'));
  const collector = {status:async () => ({channels:[{channel:channels[0],available:true,enabled:true}]}),collect:async () => ({channels:[{channel:channels[0],events:pages.shift() || [],hasMore:pages.length > 0}]})};
  const sessions = new Sessions(new Store(dir),collector,{mode:'byok',apiKey:''}); await sessions.init();
  t.after(async () => { sessions.close(); if (sessions.pending) await sessions.pending; await sessions.store.queue; await rm(dir,{recursive:true,force:true}); });
  return {sessions,dir,collector};
}
test('capture prevents overlap, deduplicates events, and drains queued pages at stop',async t => {
  const {sessions} = await create(t,[[raw(1),raw(2)],[raw(2),raw(3)],[raw(4)]]);
  const s = await sessions.start({question:'Test',duration:5});
  await assert.rejects(() => sessions.start({question:'Second'}),/Finish/);
  await sessions.stop(s.id); assert.equal(s.events.length,4); assert.equal(s.status,'complete'); assert.equal(sessions.activeId,null); assert.equal(s.cursors[channels[0]],'4');
});
test('lookback returns a completed observation without a live session',async t => { const {sessions} = await create(t,[[raw(1)]]); const s = await sessions.start({question:'Already installed',lookback:15}); assert.equal(s.status,'complete'); assert.equal(s.events.length,1); assert.equal(sessions.activeId,null); assert.ok(s.warnings.some(w => w.includes('retrospective'))); });
test('demo does not call Windows collector and is explicitly synthetic',async t => { const {sessions,collector} = await create(t); collector.status = () => {throw new Error('must not call');}; const s = await sessions.start({question:'Demo',demo:true}); assert.equal(s.events.length,8); assert.ok(s.warnings.some(w => w.includes('Synthetic'))); });
test('collection failure is visible and never removes saved evidence',async t => { const {sessions,collector} = await create(t,[[raw(1)]]); const s = await sessions.start({question:'Test'}); collector.collect = async () => {throw new Error('Access denied');}; await sessions.stop(s.id); assert.equal(s.events.length,1); assert.ok(s.report.limitations.includes('Access denied')); });
test('restart marks unfinished captures as interrupted',async t => { const {sessions,dir} = await create(t,[[raw(1)]]); const s = await sessions.start({question:'Test'}); sessions.close(); const restored = new Sessions(new Store(dir),sessions.collector,sessions.config); await restored.init(); t.after(()=>restored.close()); assert.equal(restored.get(s.id).status,'interrupted'); assert.equal(restored.activeId,null); });
test('explicit consent and credentials are required for automatic and manual AI',async t => { const {sessions} = await create(t); await assert.rejects(()=>sessions.start({question:'Test',autoAnalyze:true}),/checkbox/); const s = await sessions.start({question:'Demo',demo:true}); await assert.rejects(()=>sessions.runAnalysis(s.id,false),/consent/); await assert.rejects(()=>sessions.runAnalysis(s.id,true),/provider/); });
test('event cap is enforced and disclosed',async t => { const {sessions} = await create(t); const s = await sessions.start({question:'Test'}); s.events = Array.from({length:MAX_EVENTS},(_,i) => ({...raw(i),id:`id:${i}`})); sessions.collector.collect = async () => ({channels:[{channel:channels[0],events:[raw(99999)],hasMore:false}]}); await sessions.stop(s.id); assert.equal(s.events.length,MAX_EVENTS); assert.ok(s.warnings.some(w=>w.includes('event limit'))); });
test('credentials are not written into session files',async t => { const {sessions,dir} = await create(t); sessions.config.apiKey='sk-secret-not-for-disk'; const s = await sessions.start({question:'Demo',demo:true}); const saved = await readFile(path.join(dir,`${s.id}.json`),'utf8'); assert.ok(!saved.includes('sk-secret-not-for-disk')); });
