import { randomUUID } from 'node:crypto';
import { normalize, localReport, evidencePayload } from './events.mjs';
import { demoEvents } from './collector.mjs';
import { HttpError, validText } from './http.mjs';
import { analyze } from './analysis.mjs';
export const MAX_EVENTS = 5000;
const warn = (session, text) => { if (!session.warnings.includes(text)) session.warnings.push(text); };

export class Sessions {
  constructor(store, collector, config, analyzer = analyze) { this.store = store; this.collector = collector; this.config = config; this.analyzer = analyzer; this.items = new Map(); this.activeId = null; this.pending = null; this.stopping = null; this.lastTickError = null; }
  async init() {
    for (const s of await this.store.load()) {
      if (['observing','stopping'].includes(s.status)) { s.status = 'interrupted'; s.end = s.lastCollectedAt || s.start; warn(s,'Observe closed before this capture finished. The saved evidence is incomplete.'); }
      s.analyzing = false; this.items.set(s.id,s);
    }
    this.timer = setInterval(() => this.tick().catch(() => { this.lastTickError = 'Could not save observation data. Check free disk space and folder permissions.'; }),3000);
    this.timer.unref();
  }
  get(id) { const s = this.items.get(id); if (!s) throw new HttpError(404,'Observation not found.'); return s; }
  list() { return [...this.items.values()].sort((a,b) => b.createdAt.localeCompare(a.createdAt)).map(({events,cursors,...s}) => ({...s,eventCount:events.length})); }
  async start(input) {
    if (this.activeId) throw new HttpError(409,'Finish the current observation first.');
    if (this.items.size >= 30) throw new HttpError(409,'The MVP keeps up to 30 observations. Delete an old observation before starting another.');
    const question = validText(input.question,'question');
    const duration = Number(input.duration ?? 15), lookback = Number(input.lookback ?? 0);
    if (![5,15,30,60].includes(duration) || ![0,5,15,60,1440].includes(lookback)) throw new HttpError(400,'Choose a supported capture period.');
    if (input.autoAnalyze && !input.cloudConsent) throw new HttpError(400,'Enable the evidence-sharing checkbox to use live Astra analysis.');
    if (input.autoAnalyze && !this.ready()) throw new HttpError(400,'Configure an analysis provider in Settings first.');
    const now = new Date(), demo = input.demo === true;
    const s = { id:randomUUID(), question, focus:typeof input.focus === 'string' ? input.focus.slice(0,120) : '', demo, createdAt:now.toISOString(), start:new Date(now.getTime() - (demo ? 10_000 : lookback*60_000)).toISOString(), end:demo || lookback ? now.toISOString() : null, deadline:new Date(now.getTime()+duration*60_000).toISOString(), status:demo ? 'complete' : 'observing', events:[], cursors:{}, warnings:[], sensors:[], autoAnalyze:input.autoAnalyze === true && !demo, analysisCount:0, lastAnalysisAt:null, analyzing:false, analysisError:null, report:null };
    this.items.set(s.id,s); this.activeId = demo ? null : s.id;
    try {
      if (demo) {
        s.events = demoEvents(s.start).map(normalize);
        warn(s,'Synthetic demonstration only. These events are invented and do not describe Markdown PDF or any real installation.');
      } else {
        const status = await this.collector.status(); s.sensors = status.channels;
        for (const c of status.channels) {
          // PowerShell 7 is optional. Absence is still reported as a coverage gap.
          if (!c.available || !c.enabled || c.error) warn(s,`${c.channel}: unavailable, disabled, or unreadable. ${c.error || ''}`);
          if (c.available && c.channel.includes('PowerShell') && !c.scriptBlockPolicy) warn(s,`${c.channel}: Script Block Logging policy is not confirmed enabled. Existing 4104 events alone do not prove full coverage.`);
        }
        warn(s,'Sysmon channel availability does not confirm which event types its configuration enables. Events lost to rollover or before logging was enabled cannot be recovered.');
        if (lookback) warn(s,'This is a retrospective capture of events still retained in Windows logs. Earlier activity may be missing.');
        if (lookback) await this.stop(s.id);
        else await this.poll(s);
      }
      s.report ||= localReport(s); await this.store.save(s); return s;
    } catch (error) {
      s.status = 'interrupted'; s.end ||= new Date().toISOString(); warn(s,error.message); s.report = localReport(s); this.activeId = null; await this.store.save(s); throw error;
    }
  }
  ready() { return this.config.mode === 'byok' ? !!this.config.apiKey : !!(this.config.gateway && this.config.accessToken); }
  async poll(s) {
    if (this.pending) return this.pending;
    this.pending = (async () => {
      let result;
      try { result = await this.collector.collect(s); }
      catch (error) { warn(s,error.message); await this.store.save(s); return false; }
      const seen = new Set(s.events.map(e => e.id)); let hasMore = false;
      for (const c of result.channels) {
        if (c.error) warn(s,`${c.channel}: ${c.error}`);
        if (c.reset) { warn(s,`${c.channel}: record IDs reset during observation; the log may have been cleared. Coverage is incomplete.`); s.cursors[c.channel] = '0'; }
        hasMore ||= c.hasMore;
        for (const raw of c.events || []) {
          // A reset can reuse old IDs. Retain new event identity by its timestamp.
          const event = normalize(raw);
          if (c.reset || s.events.some(e => e.id === event.id && e.timestamp !== event.timestamp)) event.id += `:${event.timestamp}`;
          s.cursors[c.channel] = raw.recordId;
          if (!seen.has(event.id) && s.events.length < MAX_EVENTS) { s.events.push(event); seen.add(event.id); }
          else if (!seen.has(event.id)) warn(s,`Capture reached its ${MAX_EVENTS}-event limit. Additional events were omitted; coverage is incomplete.`);
        }
      }
      s.events.sort((a,b) => a.timestamp.localeCompare(b.timestamp));
      s.backlog = hasMore; s.lastCollectedAt = new Date().toISOString();
      if (!s.report || s.report.provider === 'local') s.report = localReport(s);
      await this.store.save(s); return hasMore;
    })();
    try { return await this.pending; } finally { this.pending = null; }
  }
  async tick() {
    if (!this.activeId || this.pending || this.stopping) return;
    const s = this.get(this.activeId);
    if (Date.now() >= Date.parse(s.deadline) || s.events.length >= MAX_EVENTS) { await this.stop(s.id); return; }
    await this.poll(s);
    if (s.autoAnalyze && !s.analyzing && s.analysisCount < 10 && s.events.length && Date.now()-Date.parse(s.lastAnalysisAt || s.createdAt) >= 60_000 && s.events.length !== s.lastAnalyzedEventCount) this.runAnalysis(s.id,true).catch(() => {});
  }
  async stop(id) {
    const s = this.get(id);
    if (this.stopping) return this.stopping;
    if (s.status !== 'observing') return s;
    s.status = 'stopping'; s.end ||= new Date().toISOString();
    this.stopping = (async () => {
      if (this.pending) await this.pending;
      let more = false;
      for (let page=0; page<12; page++) { more = await this.poll(s); if (!more || s.events.length >= MAX_EVENTS) break; }
      if (more) warn(s,'Collection stopped with an event backlog. Some events in the selected window were omitted.');
      s.status = 'complete'; this.activeId = null;
      if (!s.report || s.report.provider === 'local') s.report = localReport(s);
      await this.store.save(s);
      if (s.autoAnalyze && !s.analyzing && s.analysisCount < 10 && s.events.length !== s.lastAnalyzedEventCount) this.runAnalysis(id,true).catch(() => {});
      return s;
    })();
    try { return await this.stopping; } finally { this.stopping = null; }
  }
  async runAnalysis(id, consent, snapshot) {
    const s = this.get(id);
    if (consent !== true) throw new HttpError(400,'Preview the evidence and consent to sending it for analysis.');
    if (s.analyzing) throw new HttpError(409,'An analysis is already in progress.');
    if (s.analysisCount >= 10) throw new HttpError(429,'This observation reached the MVP limit of 10 AI requests.');
    if (!this.ready()) throw new HttpError(400,'Configure an analysis provider in Settings first.');
    s.analyzing = true; s.analysisError = null; s.analysisCount++; s.lastAnalysisAt = new Date().toISOString();
    const payload = snapshot || evidencePayload(s);
    try { s.report = await this.analyzer(payload,{...this.config}); s.lastAnalyzedEventCount = payload.coverage.captured; }
    catch (error) { s.analysisError = error.message; throw error; }
    finally { s.analyzing = false; await this.store.save(s); }
    return s;
  }
  async remove(id) {
    const s = this.get(id);
    if (this.activeId === id || s.analyzing) throw new HttpError(409,'Stop capture and wait for analysis before deleting.');
    await this.store.remove(id); this.items.delete(id);
  }
  close() { clearInterval(this.timer); }
}
