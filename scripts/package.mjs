import { cp, mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('..',import.meta.url));
const output = path.join(root,'dist','Observe-MVP');
await mkdir(output,{recursive:true});
for (const name of ['src','public','scripts','test','.gitignore','server.mjs','gateway.mjs','package.json','Start-Observe.cmd','Stop-Observe.cmd','README.md','LICENSE','SECURITY.md']) await cp(path.join(root,name),path.join(output,name),{recursive:true});
if (process.platform === 'win32') {
  await mkdir(path.join(output,'runtime'),{recursive:true});
  await cp(process.execPath,path.join(output,'runtime','node.exe'));
  const licenseResponse = await fetch(`https://raw.githubusercontent.com/nodejs/node/${process.version}/LICENSE`);
  if (!licenseResponse.ok) throw new Error('Could not fetch the matching Node.js license. Refusing to distribute without its license.');
  await writeFile(path.join(output,'runtime','NODE-LICENSE.txt'),await licenseResponse.text());
  const zip = path.join(root,'dist','Observe-MVP-Windows.zip');
  const quote = v => `'${v.replaceAll("'","''")}'`;
  execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',`Compress-Archive -LiteralPath ${quote(output)} -DestinationPath ${quote(zip)} -Force`],{windowsHide:true});
  console.log(zip);
} else console.log('Source package prepared. Build on Windows to include the Windows Node runtime.');
