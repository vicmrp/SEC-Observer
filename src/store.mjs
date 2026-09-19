import { mkdir, readdir, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
export class Store {
  constructor(directory) { this.directory = directory; this.queue = Promise.resolve(); }
  async init() { await mkdir(this.directory,{recursive:true,mode:0o700}); }
  file(id) { if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error('Invalid observation ID.'); return path.join(this.directory,`${id}.json`); }
  async load() {
    await this.init(); const sessions = [];
    for (const file of await readdir(this.directory)) {
      if (!/^[a-f0-9-]{36}\.json$/.test(file)) continue;
      try { sessions.push(JSON.parse(await readFile(path.join(this.directory,file),'utf8'))); } catch { /* An unreadable file must not prevent startup. */ }
    }
    return sessions;
  }
  save(session) {
    const serialized = JSON.stringify(session); const target = this.file(session.id);
    const operation = this.queue.then(async () => { await writeFile(`${target}.tmp`,serialized,{mode:0o600}); await rename(`${target}.tmp`,target); });
    this.queue = operation.catch(() => {}); return operation;
  }
  async remove(id) { await this.queue; await unlink(this.file(id)); }
}
