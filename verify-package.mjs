import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const blob=b=>crypto.createHash('sha1').update(Buffer.from(`blob ${b.length}\0`)).update(b).digest('hex');
const safe=p=>typeof p==='string'&&p.length>0&&!/[\\\x00-\x1f\x7f:]/.test(p)&&!p.startsWith('/')&&p.split('/').every(x=>x&&x!=='.'&&x!=='..');
function files(d=root){return fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>{const p=path.join(d,e.name);assert.ok(!e.isSymbolicLink(),'symbolic link');if(d===root&&['.git','node_modules'].includes(e.name))return [];return e.isDirectory()?files(p):[path.relative(root,p).replaceAll('\\','/')];}).sort();}
const inventory=files();
const manifest=JSON.parse(fs.readFileSync(path.join(root,'PACKAGE_MANIFEST.json'),'utf8'));
assert.equal(manifest.identity,'VECTORRAIL_GLORY_RC1_SANITIZED_R1');assert.deepEqual(manifest.private_inputs,[]);
const matrix=JSON.parse(fs.readFileSync(path.join(root,'PUBLIC_DISCLOSURE_MATRIX.json'),'utf8'));
assert.equal(matrix.identity,manifest.identity);assert.ok(matrix.files.every(r=>r.approved_for_publication===true&&r.classification==='PUBLIC_SAFE'));
assert.deepEqual(matrix.files.map(r=>r.path).sort(),inventory);assert.equal(new Set(matrix.files.map(r=>r.path)).size,inventory.length);
const sums=new Map();
for(const line of fs.readFileSync(path.join(root,'SHA256SUMS'),'utf8').trimEnd().split('\n')){const m=/^([a-f0-9]{64})  (.+)$/.exec(line);assert.ok(m&&safe(m[2]),'hash entry');assert.ok(!sums.has(m[2]),'duplicate hash');sums.set(m[2],m[1]);}
assert.deepEqual([...sums.keys()].sort(),inventory.filter(p=>p!=='SHA256SUMS'));
for(const [p,s]of sums)assert.equal(sha(fs.readFileSync(path.join(root,p))),s,p+' exact bytes');
assert.deepEqual(manifest.inventory.map(r=>r.path).sort(),inventory.filter(p=>!['SHA256SUMS','PACKAGE_MANIFEST.json'].includes(p)));
for(const r of manifest.inventory){assert.ok(safe(r.path));const b=fs.readFileSync(path.join(root,r.path));assert.equal(b.length,r.bytes);assert.equal(sha(b),r.sha256);assert.equal(blob(b),r.git_blob_sha);}
const secretPattern=/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{16,})\b/;
for(const p of inventory){const text=fs.readFileSync(path.join(root,p),'utf8');assert.ok(!secretPattern.test(text),p+' secret pattern');if(p.endsWith('.ts')){const specs=[...text.matchAll(/\b(?:from|import)\s*["']([^"']+)["']/g),...text.matchAll(/\b(?:import|require)\s*\(\s*["']([^"']+)["']\s*\)/g)];for(const m of specs){if(m[1].startsWith('node:'))continue;assert.ok(m[1].startsWith('.'),'external source dependency');const dest=path.resolve(root,path.dirname(p),m[1].replace(/\.js$/,'.ts'));assert.ok(dest.startsWith(root+path.sep),'outside source root');assert.ok(inventory.includes(path.relative(root,dest).replaceAll('\\','/')),'unresolved import');}}}
const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
const lock=JSON.parse(fs.readFileSync(path.join(root,'package-lock.json'),'utf8'));
assert.equal(lock.name,pkg.name);assert.equal(lock.version,pkg.version);assert.equal(lock.packages[''].name,pkg.name);assert.equal(lock.packages[''].version,pkg.version);
assert.deepEqual(lock.packages[''].devDependencies,pkg.devDependencies);
for(const [p,item]of Object.entries(lock.packages)){if(p==='')continue;const u=new URL(item.resolved);assert.equal(u.origin,'https://registry.npmjs.org');assert.equal(u.username,'');assert.equal(u.password,'');assert.match(item.integrity,/^sha512-[A-Za-z0-9+/]+=*$/);assert.ok(!item.link,'local linked dependency');}
console.log(JSON.stringify({status:'PASS',identity:manifest.identity,exact_files:inventory.length,private_inputs:0,unknown_files:0,unresolved_imports:0,secret_pattern_hits:0}));
