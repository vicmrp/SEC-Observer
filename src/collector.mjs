import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
const run = promisify(execFile);
const script = fileURLToPath(new URL('../scripts/Read-Events.ps1', import.meta.url));
export const channels = ['Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational'];

export class WindowsCollector {
  async call(mode, session) {
    if (process.platform !== 'win32') return { channels: channels.map(channel => ({ channel, available: false, enabled: false, error: 'Live capture requires Windows. The demo works on any platform.', events: [], hasMore: false })) };
    const args = ['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script,'-Mode',mode];
    if (session) args.push('-StartUtc',session.start,'-EndUtc',session.end || new Date().toISOString(),'-CursorsJson',JSON.stringify(session.cursors));
    try {
      const { stdout } = await run(`${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`, args, { windowsHide: true, timeout: 25_000, maxBuffer: 24 * 1024 * 1024, encoding: 'utf8' });
      return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
    } catch { throw new Error('Windows event collection failed or timed out. Check event-log permissions and restart Observe if necessary.'); }
  }
  status() { return this.call('status'); }
  collect(session) { return this.call('events',session); }
}

export function demoEvents(start) {
  const sys = channels[0], ps = channels[1];
  const root = '{DEMO-INSTALLER}', child = '{DEMO-POWERSHELL}';
  const image = 'C:\\Users\\demo\\Downloads\\example-installer.exe';
  const samples = [
    [sys,1,{ Image:image, ProcessGuid:root, ParentProcessGuid:'{DEMO-EXPLORER}', ParentImage:'C:\\Windows\\explorer.exe', CommandLine:'example-installer.exe /install' }],
    [sys,11,{ Image:image, ProcessGuid:root, TargetFilename:'C:\\Users\\demo\\AppData\\Local\\Example App\\app.exe' }],
    [sys,22,{ Image:image, ProcessGuid:root, QueryName:'downloads.example.com', QueryResults:'203.0.113.10' }],
    [sys,3,{ Image:image, ProcessGuid:root, DestinationHostname:'downloads.example.com', DestinationIp:'203.0.113.10', DestinationPort:'443', Protocol:'tcp' }],
    [sys,1,{ Image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ProcessGuid:child, ParentProcessGuid:root, ParentImage:image, CommandLine:'powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEQAZQBtAG8AIgA=' }],
    [ps,4104,{ ScriptBlockId:'demo-script', MessageNumber:'1', MessageTotal:'1', ScriptBlockText:'Write-Output "Demo"', Path:'' }],
    [sys,13,{ Image:image, ProcessGuid:root, TargetObject:'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ExampleApp', Details:'C:\\Users\\demo\\AppData\\Local\\Example App\\app.exe' }],
    [sys,5,{ Image:image, ProcessGuid:root }]
  ];
  return samples.map(([channel,eventId,data],i) => ({ channel,eventId,data,recordId:String(1000+i), timestamp:new Date(new Date(start).getTime() + i*1200).toISOString() }));
}
