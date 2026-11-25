import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, copyFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

test('MCP exports protected offline snapshots for both profiles at every stage', () => {
  const dir = mkdtempSync(join(tmpdir(),'bsi-test-'));
  try {
    for (const file of ['inspector.mjs','server.mjs'])
      copyFileSync(new URL(file,import.meta.url),join(dir,file));
    const chrome = join(dir,'chrome');
    const mullvad = join(dir,'mullvad');
    mkdirSync(join(chrome,'Default'),{recursive:true});
    mkdirSync(mullvad);
    writeFileSync(join(chrome,'Default','Preferences'),'{}');
    writeFileSync(join(mullvad,'prefs.js'),'');
    const fixtures = [
      [join(chrome,'Default','Cookies'),"CREATE TABLE cookies(name,host_key,path,is_secure,is_httponly,is_persistent,expires_utc,value); INSERT INTO cookies VALUES ('public_key','private.test','/',1,1,0,0,'NEVER_EXPORT')"],
      [join(mullvad,'cookies.sqlite'),"CREATE TABLE moz_cookies(name,host,path,value,isSecure,isHttpOnly,expiry,sameSite,originAttributes); INSERT INTO moz_cookies VALUES ('public_key','private.test','/','NEVER_EXPORT',1,1,1893456000,1,'')"]
    ];
    const ls = join(mullvad,'storage','default','https+++example.test','ls');
    mkdirSync(ls,{recursive:true});
    fixtures.push([join(ls,'data.sqlite'),"CREATE TABLE database(origin); INSERT INTO database VALUES ('https://private.test'); CREATE TABLE data(key,utf16_length,value); INSERT INTO data VALUES ('private-key',12,'NEVER_EXPORT')"]);
    for (const [file,sql] of fixtures) {
      const db = new DatabaseSync(file);
      db.exec(sql);
      db.close();
    }
    const before = fixtures.map(([file])=>readFileSync(file));
    writeFileSync(join(dir,'.env'),[
      'BSI_CHROME_USER_DATA_DIR='+chrome,
      'BSI_MULLVAD_PROFILE_DIR='+mullvad,
      'BSI_PUBLIC_LABELS=\'["public_key"]\''
    ].join('\n'),{mode:0o600});
    const requests = [{method:'initialize'},{method:'notifications/initialized'},{method:'tools/list'}];
    for (const browser of ['chrome','mullvad']) {
      for (const stage of ['pre_runtime','runtime','post_runtime','post_restart','manual']) {
        requests.push({method:'tools/call',params:{name:'capture_storage_snapshot',arguments:{browser,capture_stage:stage}}});
      }
    }
    requests.push({method:'tools/call',params:{name:'capture_storage_snapshot',arguments:{browser:'chrome',path:'/unexpected'}}});
    const input=requests.map((r,id)=>JSON.stringify({...r,jsonrpc:'2.0',id:id===1?undefined:id})).join('\n');
    const run=spawnSync(process.execPath,[join(dir,'server.mjs')],{input,encoding:'utf8'});
    assert.equal(run.status,0);
    const replies=run.stdout.trim().split('\n').map(JSON.parse);
    assert.equal(replies[1].result.tools[0].name,'capture_storage_snapshot');
    assert.equal(replies.at(-1).error.code,-32602);
    assert.equal(readdirSync(join(dir,'snapshots')).length,10);
    for (const r of replies.slice(2,-1)) {
      const {file}=JSON.parse(r.result.content[0].text);
      const raw=readFileSync(file,'utf8');
      assert.doesNotMatch(raw,/NEVER_EXPORT|private\.test|private-key/);
      const snap=JSON.parse(raw);
      assert.equal(snap.capture_stage,requests[r.id].params.arguments.capture_stage);
      assert.equal(snap.storage_summary.cookies,1);
      assert.equal(snap.records.cookies[0].name,'public_key');
      assert.equal(snap.collection_status.cookies,'partial');
      assert.equal(snap.storage_summary.session_storage,null);
      if (snap.browser_profile_id==='mullvad') assert.equal(snap.records.local_storage[0].value_length,12);
      assert.equal(statSync(file).mode & 0o777,0o600);
    }
    fixtures.forEach(([file],i)=>assert.deepEqual(readFileSync(file),before[i]));
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
