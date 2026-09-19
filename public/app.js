const $ = selector => document.querySelector(selector);
const token = $('meta[name="observe-token"]').content;
const state = { selectedId:null, session:null, status:null, history:[], tab:'report', page:'observe', loading:false, previewId:null, sessionSignature:null, historySignature:null };
const escape = v => String(v ?? '').replace(/[&<>"']/g,c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time = v => new Date(v).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
const date = v => new Date(v).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
const basename = v => String(v || 'Unknown').split(/[\\/]/).pop();

async function api(route, method='GET', data) {
  const response = await fetch(`/api${route}`, {method,headers:{'Content-Type':'application/json','X-Observe-Token':token},...(data !== undefined ? {body:JSON.stringify(data)} : {})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Something went wrong. Please try again.');
  return result;
}
function notice(message, error=false) { const el = $('#notice'); el.textContent = message; el.classList.toggle('error',error); el.hidden = !message; }
async function action(fn) { try { await fn(); } catch(e) { notice(e.message,true); } }
function navigate(page) {
  state.page = page;
  for (const p of ['observe','history','setup']) $(`#${p}-page`).hidden = p !== page;
  document.querySelectorAll('nav [data-nav]').forEach(b => b.classList.toggle('active',b.dataset.nav === page));
  $('#page-name').textContent = {observe:'Observation',history:'History',setup:'Sensor setup'}[page];
  if (page === 'history') renderHistory();
}
function renderStatus() {
  const status = state.status; if (!status) return;
  const names = {'Microsoft-Windows-Sysmon/Operational':'Sysmon','Microsoft-Windows-PowerShell/Operational':'PowerShell','PowerShellCore/Operational':'PowerShell 7'};
  $('#sensor-list').innerHTML = status.sensors.error ? `<p class="muted">${escape(status.sensors.error)}</p>` : status.sensors.channels.map(c => {
    const ready = c.available && c.enabled && !c.error;
    const policy = !c.channel.includes('PowerShell') || c.scriptBlockPolicy;
    const sensorLabel = ready ? policy ? 'Channel available' : 'Script policy unconfirmed' : c.serviceState === 'Running' ? 'Service running · log access denied' : c.available ? 'Channel disabled / unreadable' : 'Unavailable or access denied';
    return `<div class="sensor" title="${escape(c.error || 'Sensor availability does not guarantee complete coverage.')}"><span class="sensor-icon">${c.channel.includes('Sysmon') ? '⌘' : '›_'}</span><div class="sensor-copy"><strong>${escape(names[c.channel] || c.channel)}</strong><small>${sensorLabel}</small></div><span class="sensor-status ${ready && policy ? 'good' : ''}" aria-label="${ready && policy ? 'Available' : 'Needs attention'}"></span></div>`;
  }).join('');
  const c = status.config;
  $('#plan-label').textContent = c.mode === 'managed' ? 'Managed service' : 'Bring your own key';
  $('#ai-state').textContent = c.ready ? 'Configured · ready to analyze' : 'Connect in Settings';
  $('#observe-button').disabled = !!status.activeId || state.loading;
  $('#demo-button').disabled = !!status.activeId || state.loading;
  $('#live-consent-text').textContent = `Send minimized event data to ${c.mode === 'byok' ? 'OpenAI' : `${c.gateway || 'your managed service'} and OpenAI`} during this observation. Commands and scripts may contain sensitive information.`;
  if (status.storageError) notice(status.storageError,true);
}
async function refreshStatus(force=false) { state.status = await api(`/status${force ? '?refresh=1' : ''}`); renderStatus(); }
async function refreshHistory() { state.history = await api('/sessions'); $('#history-count').textContent = state.history.length; if (state.page === 'history') renderHistory(); }
function renderHistory() {
  const signature = JSON.stringify(state.history); if (signature === state.historySignature) return; state.historySignature = signature;
  $('#history-list').innerHTML = state.history.length ? state.history.map(s => `<article class="history-card"><div><span class="badge ${s.status === 'observing' ? 'live' : 'neutral'}">${escape(s.demo ? 'SYNTHETIC DEMO' : s.status.toUpperCase())}</span><h3>${escape(s.question)}</h3><p>${escape(date(s.createdAt))} · ${s.eventCount} events · ${s.report?.provider === 'local' ? 'Local triage' : 'AI assessment'}</p></div><div class="history-actions"><button class="button subtle" data-open="${escape(s.id)}">Open ↗</button><button class="button subtle" data-delete="${escape(s.id)}" ${['observing','stopping'].includes(s.status) || s.analyzing ? 'disabled' : ''}>Delete</button></div></article>`).join('') : '<div class="empty-history">Your observations will appear here. Start a capture or explore the demo.</div>';
}
async function selectSession(id) { state.selectedId = id; state.session = await api(`/sessions/${id}`); navigate('observe'); renderSession(); }
function setTab(tab) {
  state.tab = tab;
  for (const name of ['report','timeline','processes']) $(`#${name}-tab`).hidden = tab !== name;
  document.querySelectorAll('[data-tab]').forEach(b => { b.classList.toggle('selected',b.dataset.tab === tab); b.setAttribute('aria-selected',String(b.dataset.tab === tab)); });
}
function renderSession() {
  const s = state.session;
  $('#session-panel').hidden = !s; $('#empty-panel').hidden = !!s;
  if (!s) { state.sessionSignature = null; return; }
  const signature = JSON.stringify(s); if (signature === state.sessionSignature) return; state.sessionSignature = signature;
  $('#session-title').textContent = s.question;
  $('#session-time').textContent = `${date(s.start)} → ${s.end ? date(s.end) : 'now'}${s.focus ? ` · Focus: ${s.focus}` : ''}`;
  const live = ['observing','stopping'].includes(s.status);
  $('#session-tag').textContent = s.demo ? 'SYNTHETIC DEMO' : s.status === 'observing' ? '● OBSERVING' : s.status.toUpperCase();
  $('#session-tag').className = `badge ${live ? 'live' : 'neutral'}`;
  $('#demo-banner').hidden = !s.demo;
  $('#stop-button').hidden = !live; $('#stop-button').disabled = s.status === 'stopping';
  $('#metric-events').textContent = s.events.length.toLocaleString();
  $('#metric-processes').textContent = s.events.filter(e => e.eventId === 1).length;
  $('#metric-network').textContent = s.events.filter(e => e.category === 'network').length;
  $('#metric-signals').textContent = s.report?.findings.length || 0;
  $('#analyze-button').disabled = s.analyzing || s.status === 'stopping';
  $('#analyze-button').textContent = s.analyzing ? 'Astra is analyzing…' : 'Preview & analyze ↗';
  $('#analysis-caption').textContent = s.analysisError || (s.analyzing ? 'Your evidence is being assessed. You can keep using Observe.' : s.autoAnalyze && live ? `Live Astra review enabled · ${s.analysisCount}/10 requests used` : 'Review exactly what Astra will receive.');
  renderReport(); renderTimeline(); renderProcesses(); setTab(state.tab);
}
function renderReport() {
  const s = state.session, r = s.report; if (!r) { $('#report-tab').innerHTML = '<p class="muted">Collecting evidence…</p>'; return; }
  const names = {no_observed_indicators:'No indicators in this evidence',review:'A few things to look at',suspicious:'Suspicious activity observed',insufficient_evidence:'More evidence is needed'};
  const limits = [...new Set([...r.limitations,...s.warnings])];
  const previousOpen = $('#report-tab details')?.open;
  $('#report-tab').innerHTML = `<div class="report-label">${r.provider === 'local' ? 'LOCAL TRIAGE · ASTRA HAS NOT REVIEWED THIS' : 'ASTRA ASSESSMENT · '+escape(date(r.analyzedAt))}</div><h3 class="report-verdict">${escape(names[r.verdict] || r.verdict)}</h3><p class="report-summary">${escape(r.summary)}</p>${r.provider !== 'local' && s.events.length !== s.lastAnalyzedEventCount ? '<div class="demo-banner">More events arrived after this assessment. Review a fresh snapshot for an updated report.</div>' : ''}${r.findings.map(f => `<article class="finding"><h3><span class="severity ${escape(f.severity)}">${escape(f.severity)}</span>${escape(f.title)}</h3><p>${escape(f.detail)}</p><p class="recommendation">${escape(f.recommendation)}</p>${f.evidenceIds.map(id => `<button class="evidence-link" data-event="${escape(id)}">Event ${escape(s.events.find(e => e.id === id)?.recordId || '?')} ↗</button>`).join('')}</article>`).join('')}<details class="limitations" ${previousOpen ? 'open' : ''}><summary>Coverage & limitations (${limits.length})</summary><ul>${limits.map(l => `<li>${escape(l)}</li>`).join('')}</ul></details>${r.nextSteps.length ? `<div class="limitations"><strong>Next steps</strong><ul class="next-steps">${r.nextSteps.map(n => `<li>${escape(n)}</li>`).join('')}</ul></div>` : ''}`;
}
function renderTimeline() {
  const s = state.session; if (!s) return;
  const q = $('#event-search').value.toLowerCase();
  const filtered = s.events.filter(e => !q || JSON.stringify(e).toLowerCase().includes(q));
  const symbols = {process:'⌘',network:'↗',powershell:'›_',file:'▤',persistence:'⌁'};
  $('#timeline').innerHTML = filtered.slice(-200).reverse().map(e => `<button class="event-row" data-event="${escape(e.id)}"><span class="event-time">${escape(time(e.timestamp))}</span><span class="event-kind">${symbols[e.category] || '·'}</span><span><strong>${escape(e.label)} · ${escape(e.process)}</strong><small>${escape(e.data.TargetFilename || e.data.TargetObject || e.data.QueryName || e.data.DestinationHostname || e.data.DestinationIp || e.data.CommandLine || e.data.ScriptBlockText || 'Event '+e.recordId)}</small></span><span class="event-arrow">↗</span></button>`).join('') || '<p class="muted">No events match. Logs may be missing or nothing has been captured yet.</p>';
  if (filtered.length > 200) $('#timeline').insertAdjacentHTML('beforeend',`<p class="muted">Showing the latest 200 of ${filtered.length} matching events. Export to inspect the full capture.</p>`);
}
function renderProcesses() {
  const events = state.session.events.filter(e => e.eventId === 1);
  const ids = new Set(events.map(e => e.data.ProcessGuid).filter(Boolean));
  $('#processes-tab').innerHTML = '<p class="muted">Connections use Sysmon ProcessGuid and ParentProcessGuid. A shared time window alone does not establish a relationship.</p>'+events.slice(0,200).map(e => `<div class="tree-node ${ids.has(e.data.ParentProcessGuid) ? 'tree-indent' : ''}"><strong>${escape(basename(e.data.ParentImage))}</strong> → <strong>${escape(e.process)}</strong><small>${escape(e.data.CommandLine || '')}</small><small>Process ${escape(e.data.ProcessGuid || 'unknown')} · Parent ${escape(e.data.ParentProcessGuid || 'unknown')}</small><button class="evidence-link" data-event="${escape(e.id)}">View process event ↗</button></div>`).join('')+(events.length ? events.length > 200 ? '<p class="muted">First 200 process starts shown. Export includes the complete capture.</p>' : '' : '<p class="muted">No process-start events captured. Check Sysmon configuration and permissions.</p>');
}
function showSettings() {
  const c = state.status.config; $('#provider-mode').value = c.mode; $('#api-key').value = ''; $('#access-token').value = ''; $('#gateway-url').value = c.gateway; $('#clear-credentials').checked = false;
  $('#key-status').textContent = c.hasApiKey ? 'A key is configured. Leave blank to keep it.' : 'No API key is configured.';
  $('#access-status').textContent = c.hasAccessToken ? 'A token is configured. Leave blank to keep it.' : 'No access token is configured.';
  providerFields(); $('#settings-dialog').showModal();
}
function providerFields() { const byok = $('#provider-mode').value === 'byok'; $('#byok-fields').hidden = !byok; $('#managed-fields').hidden = byok; }

document.addEventListener('click',event => {
  const b = event.target.closest('button'); if (!b) return;
  if (b.dataset.nav) navigate(b.dataset.nav);
  if (b.dataset.action === 'settings') { if (state.status) showSettings(); }
  if (b.dataset.close) $(`#${b.dataset.close}`).close();
  if (b.dataset.prompt) { $('#question').value = b.dataset.prompt; $('#question').focus(); }
  if (b.dataset.tab) setTab(b.dataset.tab);
  if (b.dataset.open) action(() => selectSession(b.dataset.open));
  if (b.dataset.event) { const e = state.session?.events.find(e => e.id === b.dataset.event); if (e) { $('#event-content').textContent = JSON.stringify(e,null,2); $('#event-dialog').showModal(); } }
  if (b.dataset.delete && confirm('Delete this local observation and its saved evidence? This cannot be undone.')) action(async () => { await api(`/sessions/${b.dataset.delete}`,'DELETE'); if (state.selectedId === b.dataset.delete) { state.selectedId = null; state.session = null; renderSession(); } await refreshHistory(); });
});
$('#capture-window').addEventListener('change',() => { const live = $('#capture-window').value === 'live'; $('#duration-label').hidden = !live; $('#auto-analyze').disabled = !live; if (!live) $('#auto-analyze').checked = false; $('#live-consent-row').hidden = !$('#auto-analyze').checked; });
$('#auto-analyze').addEventListener('change',() => { $('#live-consent-row').hidden = !$('#auto-analyze').checked; });
$('#provider-mode').addEventListener('change',providerFields);
$('#event-search').addEventListener('input',renderTimeline);
$('#observe-button').addEventListener('click',() => action(() => start(false)));
$('#demo-button').addEventListener('click',() => action(() => start(true)));
async function start(demo) {
  if (state.loading) return;
  const question = $('#question').value.trim();
  if (!demo && !question) { notice('Tell Observe what you would like to check.'); $('#question').focus(); return; }
  state.loading = true; renderStatus(); notice(demo ? 'Preparing the synthetic demo…' : 'Opening the observation window…');
  try {
    const s = await api('/start','POST',{ question:demo ? 'What happened during this example installation?' : question, focus:demo ? 'example-installer.exe' : $('#focus').value, duration:Number($('#duration').value), lookback:$('#capture-window').value === 'live' ? 0 : Number($('#capture-window').value), autoAnalyze:!demo && $('#auto-analyze').checked, cloudConsent:$('#live-consent').checked, demo });
    state.selectedId = s.id; state.session = s; state.tab = 'report'; renderSession(); notice(''); await refreshHistory(); await refreshStatus();
    $('#session-panel').scrollIntoView({behavior:'smooth',block:'start'});
  } finally { state.loading = false; renderStatus(); }
}
$('#stop-button').addEventListener('click',() => action(async () => { $('#stop-button').disabled = true; $('#stop-button').textContent = 'Finishing…'; try { state.session = await api(`/sessions/${state.selectedId}/stop`,'POST',{}); await refreshStatus(); renderSession(); await refreshHistory(); } finally { $('#stop-button').textContent = 'Stop capture'; } }));
$('#export-button').addEventListener('click',() => action(async () => {
  const data = await api(`/sessions/${state.selectedId}/export`); const blob = new Blob([JSON.stringify(data,null,2)],{type:'application/json'}); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `observe-${state.selectedId}.json`; link.click(); URL.revokeObjectURL(url);
}));
$('#analyze-button').addEventListener('click',() => action(async () => {
  const preview = await api(`/sessions/${state.selectedId}/preview`); state.previewId = preview.previewId;
  const p = preview.payload;
  $('#preview-content').textContent = JSON.stringify(p,null,2);
  $('#preview-summary').textContent = `${p.coverage.included} of ${p.coverage.captured} events included · ${p.coverage.omitted} omitted · ${p.coverage.shortenedFields} fields shortened. This snapshot is fixed; newer events will not be sent in this request.`;
  const c = state.status.config;
  $('#analysis-consent-text').textContent = `Send this evidence to ${c.mode === 'byok' ? 'OpenAI' : `${c.gateway} and OpenAI`} for Astra analysis. ${c.mode === 'byok' ? 'API usage will be billed to your OpenAI account.' : 'This uses your service allowance.'}`;
  $('#analysis-consent').checked = false; $('#confirm-analysis').disabled = c.ready; $('#confirm-analysis').textContent = c.ready ? 'Analyze with Astra ↗' : 'Connect Astra in Settings'; $('#preview-dialog').showModal();
}));
$('#analysis-consent').addEventListener('change',() => { $('#confirm-analysis').disabled = state.status.config.ready && !$('#analysis-consent').checked; });
$('#confirm-analysis').addEventListener('click',() => action(async () => { if (!state.status.config.ready) { $('#preview-dialog').close(); showSettings(); return; } $('#confirm-analysis').disabled = true; await api(`/sessions/${state.selectedId}/analyze`,'POST',{consent:$('#analysis-consent').checked,previewId:state.previewId}); $('#preview-dialog').close(); state.session = await api(`/sessions/${state.selectedId}`); renderSession(); }));
$('#settings-form').addEventListener('submit',event => { event.preventDefault(); action(async () => {
  const payload = {mode:$('#provider-mode').value,gateway:$('#gateway-url').value};
  if ($('#clear-credentials').checked) { payload.apiKey = ''; payload.accessToken = ''; }
  else { if ($('#api-key').value) payload.apiKey = $('#api-key').value; if ($('#access-token').value) payload.accessToken = $('#access-token').value; }
  state.status.config = await api('/config','POST',payload); $('#api-key').value = ''; $('#access-token').value = ''; $('#settings-dialog').close(); renderStatus(); notice('Settings saved for this run. Capture remains local until you enable AI analysis.');
}); });
for (const id of ['refresh-sensors','setup-refresh']) $(`#${id}`).addEventListener('click',() => action(async () => { await refreshStatus(true); notice('Device readiness refreshed.'); }));
let polling = false;
async function poll() {
  if (polling || state.loading) return; polling = true;
  try {
    if (state.selectedId) { state.session = await api(`/sessions/${state.selectedId}`); renderSession(); }
    if (state.status?.activeId && state.session?.status !== 'observing') await refreshStatus();
    await refreshHistory();
  } catch(e) { notice(`Connection interrupted: ${e.message}`,true); }
  finally { polling = false; }
}
await action(async () => { await refreshStatus(); await refreshHistory(); if (state.status.activeId) await selectSession(state.status.activeId); });
setInterval(poll,3000);
