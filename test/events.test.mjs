import test from 'node:test';
import assert from 'node:assert/strict';
import { normalize, detect, redact, evidencePayload, localReport } from '../src/events.mjs';
import { demoEvents } from '../src/collector.mjs';
import { openAIAnalysis, validateReport } from '../src/analysis.mjs';
const session = () => ({ question:'Check this install',focus:'app.exe',start:'2026-01-01T00:00:00Z',end:'2026-01-01T00:01:00Z',demo:true,warnings:[],sensors:[],events:demoEvents('2026-01-01T00:00:00Z').map(normalize) });
const report = () => ({verdict:'review',summary:'Inspect this behavior.',findings:[],limitations:[],nextSteps:[]});

test('normalizes process identity and preserves parent GUIDs',() => { const e = session().events[4]; assert.equal(e.process,'powershell.exe'); assert.equal(e.data.ParentProcessGuid,'{DEMO-INSTALLER}'); assert.equal(e.id,'Microsoft-Windows-Sysmon/Operational:1004'); });
test('demo flags encoding and startup persistence without claiming malware',() => { const s = session(); const f = detect(s.events); assert.equal(f.length,2); assert.ok(f.every(x => x.evidenceIds.length)); assert.equal(localReport(s).verdict,'review'); });
test('no matching behavior does not produce a clean verdict',() => { const s = session(); s.events = []; assert.equal(localReport(s).verdict,'insufficient_evidence'); });
test('redacts identities and common secrets recursively',() => {
  const clean = redact({User:'alice',CommandLine:'C:\\Users\\alice\\setup.exe --password="hello world" token=abc sk-abcdefghijklmnop Bearer abcd.efghi',nested:['api_key=abc']});
  assert.equal(clean.User,'[redacted identity]'); assert.ok(!JSON.stringify(clean).includes('alice')); assert.ok(!clean.CommandLine.includes('hello world')); assert.ok(!clean.CommandLine.includes('abcdefghijklmnop')); assert.equal(clean.nested[0],'api_key=[redacted]');
});
test('payload is bounded, reports omission, and prioritizes detected behavior',() => {
  const s = session(); const suspicious = s.events[4]; s.events = Array.from({length:700},(_,i) => ({...s.events[0],id:`e:${i}`,data:{Image:'a.exe',CommandLine:'x'.repeat(8000)}})); s.events.push(suspicious);
  const p = evidencePayload(s); assert.ok(p.events.length <= 350); assert.ok(p.coverage.omitted > 0); assert.ok(p.coverage.shortenedFields > 0); assert.ok(p.events.find(e => e.id === suspicious.id)); assert.ok(Buffer.byteLength(JSON.stringify(p)) < 220_000);
});
test('provider evidence references are validated',() => {
  const p = evidencePayload(session()); const r = report(); r.findings = [{severity:'high',title:'Claim',detail:'Unsupported',evidenceIds:['made-up'],recommendation:'Review'}]; assert.throws(() => validateReport(r,p),/valid evidence/);
});
test('empty evidence forces insufficient evidence even if provider says otherwise',() => { const s = session(); s.events = []; const r = report(); r.verdict = 'no_observed_indicators'; assert.equal(validateReport(r,evidencePayload(s)).verdict,'insufficient_evidence'); });
test('Responses request uses Astra, structured outputs, store:false, and no tools',async () => {
  let sent; const p = evidencePayload(session());
  const r = await openAIAnalysis(p,'test-key',{fetchImpl:async (url,options) => { assert.equal(url,'https://api.openai.com/v1/responses'); sent=JSON.parse(options.body); return {ok:true,json:async () => ({status:'completed',output:[{content:[{type:'output_text',text:JSON.stringify(report())}]}]})}; }});
  assert.equal(sent.model,'gpt-6-astra'); assert.equal(sent.store,false); assert.equal(sent.text.format.strict,true); assert.equal(sent.tools,undefined); assert.equal(sent.temperature,undefined); assert.equal(r.provider,'openai');
});
test('refused and incomplete model output does not become a successful assessment',async () => {
  await assert.rejects(() => openAIAnalysis(evidencePayload(session()),'key',{fetchImpl:async () => ({ok:true,json:async () => ({status:'incomplete'})})}),/did not finish/);
  await assert.rejects(() => openAIAnalysis(evidencePayload(session()),'key',{fetchImpl:async () => ({ok:true,json:async () => ({status:'completed',output:[{content:[{type:'refusal',refusal:'No'}]}]})})}),/usable report/);
});
test('provider failures do not expose keys or upstream response bodies',async () => { await assert.rejects(() => openAIAnalysis(evidencePayload(session()),'secret-key',{fetchImpl:async () => ({ok:false,status:401,text:async ()=>'secret-key'})}),e => !e.message.includes('secret-key') && /401/.test(e.message)); });
