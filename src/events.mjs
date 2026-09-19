const labels = { 1: 'Process started', 3: 'Network connection', 5: 'Process ended', 7: 'Image loaded', 8: 'Remote thread', 10: 'Process access', 11: 'File created', 12: 'Registry object', 13: 'Registry value', 14: 'Registry renamed', 15: 'File stream', 19: 'WMI filter', 20: 'WMI consumer', 21: 'WMI binding', 22: 'DNS query', 23: 'File deleted', 25: 'Process tampering', 26: 'File deleted', 4103: 'PowerShell module', 4104: 'PowerShell script' };
export const basename = value => String(value || '').split(/[\\/]/).pop();
export function normalize(raw) {
  const data = raw.data || {};
  const eventId = Number(raw.eventId);
  return { id: `${raw.channel}:${raw.recordId}`, channel: raw.channel, recordId: String(raw.recordId), eventId, timestamp: raw.timestamp, category: eventId === 3 || eventId === 22 ? 'network' : eventId >= 4103 ? 'powershell' : [11,15,23,26].includes(eventId) ? 'file' : [12,13,14,19,20,21].includes(eventId) ? 'persistence' : 'process', label: labels[eventId] || `Event ${eventId}`, process: basename(data.Image || data.Application || data.Path || (eventId >= 4103 ? 'PowerShell' : 'Unknown')), data };
}

export function detect(events) {
  const findings = [];
  const add = (event, severity, title, detail) => findings.push({ severity, title, detail, evidenceIds: [event.id], recommendation: 'Inspect this event and its parent process. Verify the software publisher and whether this action was expected.' });
  for (const e of events) {
    const d = e.data;
    const command = String(d.CommandLine || d.ScriptBlockText || d.Payload || '');
    if (/\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(command + ' ' + e.process) && /(?:^|\s)-(?:enc|encodedcommand|e)\s+[a-z0-9+/=]{12,}/i.test(command)) add(e, 'medium', 'Encoded PowerShell command', 'Encoding can hide a command, but is also used by legitimate installers. This signal alone does not establish malware.');
    if (/\b(?:DownloadString|DownloadData|Invoke-WebRequest|iwr|curl)\b/i.test(command) && /\b(?:Invoke-Expression|iex)\b/i.test(command)) add(e, 'high', 'Download followed by script execution', 'The command combines downloading content with evaluating a script. Review the source and process ancestry.');
    if ([11,13].includes(e.eventId) && /\\(?:CurrentVersion\\Run(?:Once)?(?:\\|$)|Start Menu\\Programs\\Startup\\)/i.test(d.TargetObject || d.TargetFilename || '')) add(e, 'medium', 'Startup persistence changed', 'A file or registry value was written to a startup location. Legitimate applications can do this too.');
    if (/Set-MpPreference[\s\S]*(?:DisableRealtimeMonitoring|DisableBehaviorMonitoring)[\s\S]*(?:\$true|\b1\b)/i.test(command)) add(e, 'high', 'Security protection change requested', 'A script attempted to disable Defender monitoring. A logged command does not prove it succeeded.');
    if (e.eventId === 25) add(e, 'high', 'Sysmon reported process tampering', 'Sysmon emitted a process-tampering event. Review the affected image and parent process.');
    if (e.eventId === 10 && /\\lsass\.exe$/i.test(d.TargetImage || '')) add(e, 'medium', 'Access to a sensitive Windows process', 'A process accessed LSASS. Security software can legitimately do this; inspect the source image and access mask.');
  }
  return findings;
}

export function localReport(session) {
  const findings = detect(session.events);
  return { provider: 'local', verdict: findings.length ? 'review' : 'insufficient_evidence', summary: findings.length ? `${findings.length} behavior signal${findings.length === 1 ? '' : 's'} need review. Local rules identify patterns; they do not determine whether software is malicious.` : 'No local rule matched the captured events. This does not establish that the installation or computer is safe.', findings, limitations: [...session.warnings, 'Activity in the same time window is not automatically caused by the application you are investigating.', 'Only the configured Windows event channels and enabled event types are visible.', 'This is a rule-based triage result. Astra has not analyzed these events.'], nextSteps: ['Check the parent process and event details for any finding.', 'Preview the evidence before requesting an Astra assessment.'], analyzedAt: new Date().toISOString(), eventCount: session.events.length };
}

// Best-effort minimization, not a promise that every secret can be detected.
export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, /^(?:User|UserName|Computer|HostName)$/i.test(k) ? '[redacted identity]' : redact(v)]));
  if (typeof value !== 'string') return value;
  return value.replace(/C:\\Users\\[^\\\s"']+/gi, 'C:\\Users\\[user]').replace(/\bsk-[A-Za-z0-9_-]{10,}/g, '[redacted key]').replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, '$1[redacted]').replace(/((?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s&;]+)/gi, '$1[redacted]').replace(/([?&](?:token|key|secret|password)=)[^&\s]+/gi, '$1[redacted]');
}

export function evidencePayload(session) {
  const matched = new Set(detect(session.events).flatMap(f => f.evidenceIds));
  const ordered = [...session.events].sort((a,b) => Number(matched.has(b.id)) - Number(matched.has(a.id)));
  const selected = []; let bytes = 0; let shortenedFields = 0;
  for (const event of ordered) {
    const clean = redact(event);
    for (const [k,v] of Object.entries(clean.data)) if (typeof v === 'string' && v.length > 6000) { clean.data[k] = v.slice(0,6000) + ' [TRUNCATED]'; shortenedFields++; }
    const size = Buffer.byteLength(JSON.stringify(clean));
    if (bytes + size > 160_000 || selected.length >= 350) continue;
    bytes += size; selected.push(clean);
  }
  selected.sort((a,b) => a.timestamp.localeCompare(b.timestamp));
  return { question: redact(session.question), focus: redact(session.focus), start: session.start, end: session.end || new Date().toISOString(), demo: session.demo, coverage: redact({ captured: session.events.length, included: selected.length, omitted: session.events.length - selected.length, shortenedFields, warnings: session.warnings, sensors: session.sensors }), events: selected, rules: detect(selected).slice(0,20), privacy: 'Identity and common-secret redaction is best effort. Commands and scripts may still contain sensitive information.' };
}
