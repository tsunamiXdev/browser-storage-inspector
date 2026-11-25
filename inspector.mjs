import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { readdirSync, existsSync, readFileSync, realpathSync, mkdirSync, mkdtempSync, writeFileSync, renameSync, rmSync, statSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export const stages = ['pre_runtime','runtime','post_runtime','post_restart','manual'];
const types = ['cookies','local_storage','session_storage','indexed_db','service_workers','cache_storage'];
const fields = 'name origin domain path party_type partition_key persistent expires_at value_length http_only secure same_site'.split(' ');
const blank = Object.fromEntries(fields.map(key => [key, null]));

async function connect(port, route) {
  if (route !== '/session' && !/^\/devtools\/browser\/[\w-]+$/.test(route)) throw Error();
  const socket = new WebSocket('ws://127.0.0.1:' + port + route);
  await new Promise((ok, fail) => {
    const timer = setTimeout(() => { socket.close(); fail(Error()); }, 3000);
    socket.onopen = () => { clearTimeout(timer); ok(); };
    socket.onerror = () => { clearTimeout(timer); fail(Error()); };
  });
  let id = 0;
  const pending = new Map();
  socket.onmessage = ({data}) => {
    const msg = JSON.parse(data);
    pending.get(msg.id)?.(msg);
  };
  socket.onclose = () => { for (const finish of pending.values()) finish({error:true}); };
  return {
    close: () => socket.close(),
    call(method, params = {}, sessionId) {
      const key = ++id;
      return new Promise((ok, fail) => {
        const finish = msg => {
          clearTimeout(timer);
          pending.delete(key);
          if (msg.error) fail(Error()); else ok(msg.result);
        };
        const timer = setTimeout(() => finish({error:true}), 5000);
        pending.set(key, finish);
        socket.send(JSON.stringify({id:key, method, params, sessionId}));
      });
    }
  };
}

function diskCookies(profile, add, label) {
  const file = [join(profile,'Network','Cookies'), join(profile,'Cookies')].find(existsSync);
  if (!file) throw Error();
  const rows = readStable(file, db => {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cookies'").get()) throw Error();
    const columns = new Set(db.prepare('PRAGMA table_info(cookies)').all().map(c => c.name));
    const opt = name => columns.has(name) ? name : 'NULL AS '+name;
    const query = 'SELECT name,host_key,path,is_secure,is_httponly,is_persistent,expires_utc,'+
      [opt('top_frame_site_key'), opt('samesite')].join(',')+' FROM cookies';
    return db.prepare(query).all();
  });
  for (const c of rows) {
    const expiration = c.is_persistent && c.expires_utc ? Number(c.expires_utc)/1000-11644473600000 : null;
    add('cookies', {name:label(c.name),domain:label(c.host_key),path:label(c.path),
      partition_key:label(c.top_frame_site_key),persistent:!!c.is_persistent,
      secure:!!c.is_secure,http_only:!!c.is_httponly,
      same_site:({0:'None',1:'Lax',2:'Strict'})[c.samesite]??null,
      expires_at:expiration === null ? null : new Date(expiration).toISOString()});
  }
}

export async function capture(stage, env) {
  if (!stages.includes(stage)) throw Error('Invalid capture stage');
  const mullvad = env.BSI_BROWSER === 'mullvad';
  const root = realpathSync(env.BSI_USER_DATA_DIR);
  const id = env.BSI_PROFILE_ID;
  if (!/^[a-zA-Z0-9_-]{1,48}$/.test(id??'') || !existsSync(mullvad ? join(root,'prefs.js') : join(root,'Default','Preferences'))) throw Error('Invalid audit profile configuration');
  const labels = JSON.parse(env.BSI_PUBLIC_LABELS || '[]');
  if (!Array.isArray(labels) || !labels.every(x=>typeof x==='string')) throw Error('Invalid public labels');
  const allowed = new Set(labels);
  const label = value => allowed.has(value) ? value : null;
  const output = resolve(env.BSI_OUTPUT_DIR || 'snapshots');
  // Check existing ancestors before creating anything.
  let parent = output;
  while (!existsSync(parent)) parent = resolve(parent,'..');
  const destination = resolve(realpathSync(parent), '.'+sep+output.slice(parent.length));
  const protectedRoots = [root,...(env.protectedProfiles??[]).filter(existsSync).map(p=>realpathSync(p))];
  if (protectedRoots.some(p=>destination===p || destination.startsWith(p+sep))) throw Error('Output inside profile');
  const time = new Date().toISOString();
  const snap = {schema_version:1,snapshot_id:randomUUID(),browser_profile_id:id,captured_at:time,
    capture_stage:stage,browser_name:mullvad ? 'Mullvad Browser' : 'Chrome',browser_version:null,storage_summary:{},
    collection_status:{},collection_errors:[],records:Object.fromEntries(types.map(t=>[t,[]]))};
  const observed = new Set();
  const errors = (type,code) => {
    if (!snap.collection_errors.some(e=>e.storage_type===type && e.code===code))
      snap.collection_errors.push({storage_type:type,code});
  };
  const add = (t,row) => snap.records[t].push({...blank,storage_type:t,...row});
  let client;
  let sessionOwned = false;
  if (mullvad) {
    try {
      const endpoint = JSON.parse(readFileSync(join(root,'WebDriverBiDiServer.json'),'utf8'));
      if (!Number.isInteger(endpoint.ws_port) || endpoint.ws_port<1 || endpoint.ws_port>65535) throw Error();
      client = await connect(endpoint.ws_port,'/session');
      const {capabilities:c} = await client.call('session.new',{capabilities:{}});
      sessionOwned = true;
      if (realpathSync(c['moz:profile']) !== root || c.browserName !== 'mullvadbrowser') throw Error();
      snap.browser_version=c.browserVersion;
      await mullvadTabs(client,add,label,observed,errors);
    } catch { for (const t of types.slice(1)) errors(t,'live_context_unavailable'); }
    finally { if (sessionOwned) await client.call('session.end').catch(()=>{}); client?.close(); }
    if (!observed.has('local_storage')) {
      try {
        const base=join(root,'storage','default');
        for (const origin of readdirSync(base,{withFileTypes:true})) {
          if (!origin.isDirectory()) continue;
          const file=join(base,origin.name,'ls','data.sqlite');
          if (!existsSync(file)) continue;
          const rows=readStable(file,db=>{
            const columns=db.prepare('PRAGMA table_info(data)').all();
            const len=['utf16_length','utf16Length'].find(k=>columns.some(c=>c.name===k))??'NULL';
            const metadata=db.prepare('SELECT origin FROM database LIMIT 1').get();
            return db.prepare('SELECT key,'+len+' AS n FROM data').all().map(r=>({
              name:label(r.key),origin:label(metadata?.origin),value_length:r.n}));
          });
          for (const r of rows) add('local_storage',r);
        }
        observed.add('local_storage');
        errors('local_storage','persisted_view_only');
      } catch { errors('local_storage','disk_store_unavailable'); }
    }
    if (!observed.has('cookies')) {
      try { firefoxCookies(root,add,label); observed.add('cookies'); errors('cookies','persisted_view_only'); }
      catch { errors('cookies','cookie_store_unavailable'); }
    }
  } else {
    try {
      const [port, route] = readFileSync(join(root,'DevToolsActivePort'),'utf8').trim().split(/\r?\n/);
      if (!/^\d{1,5}$/.test(port) || +port>65535) throw Error();
      client = await connect(port,route);
      const {product} = await client.call('Browser.getVersion');
      const [browser,version] = product.split('/');
      snap.browser_name = browser;
      snap.browser_version = version;
      const {cookies} = await client.call('Storage.getCookies');
      for (const c of cookies) add('cookies',{name:label(c.name),domain:label(c.domain),path:label(c.path),
        partition_key:label(c.partitionKey?.topLevelSite),persistent:!c.session,
        party_type:c.partitionKey?.hasCrossSiteAncestor===true?'third_party':c.partitionKey?.hasCrossSiteAncestor===false?'first_party':null,
        expires_at:c.session || c.expires<=0 ? null : new Date(c.expires*1000).toISOString(),
        value_length:Buffer.byteLength(c.value),http_only:c.httpOnly,secure:c.secure,same_site:c.sameSite??null});
      observed.add('cookies');
    } catch {
      snap.records.cookies.length=0;
      try {
        diskCookies(join(root,'Default'),add,label);
        observed.add('cookies');
        errors('cookies','persisted_view_only');
      } catch { snap.records.cookies.length=0; errors('cookies','cookie_store_unavailable'); }
    }
    try {
      if (!client) throw Error();
      await collectTabs(client,add,label,observed,errors);
    } catch {
      for (const t of types.slice(1)) errors(t,'live_context_unavailable');
    } finally { client?.close(); }
  }
  try {
    if (mullvad) {
      const compatibility=readFileSync(join(root,'compatibility.ini'),'utf8');
      const version=compatibility.match(/^LastMullvadBrowserVersion=([0-9.]+)$/m)?.[1];
      if (version) snap.browser_version=version;
    } else if (!snap.browser_version) {
      const version=readFileSync(join(root,'Last Version'),'utf8').trim();
      if (/^[0-9.]+$/.test(version)) snap.browser_version=version;
    }
  } catch { /* Older profiles may lack version metadata. */ }
  for (const t of types) {
    const ok = observed.has(t) || snap.records[t].length>0;
    snap.collection_status[t] = ok ? (snap.collection_errors.some(e=>e.storage_type===t) ? 'partial':'complete') : 'unavailable';
    snap.storage_summary[t] = ok ? snap.records[t].length : null;
  }
  mkdirSync(output,{recursive:true,mode:0o700});
  const temp = mkdtempSync(join(output,'.capture-'));
  const file = join(output,id+'_'+time.replaceAll(':','-')+'_'+stage+'_'+snap.snapshot_id+'.json');
  try {
    writeFileSync(join(temp,'snapshot'),JSON.stringify(snap),{mode:0o600});
    renameSync(join(temp,'snapshot'),file);
  } finally { rmSync(temp,{recursive:true,force:true}); }
  return {file,storage_summary:snap.storage_summary,collection_status:snap.collection_status,collection_errors:snap.collection_errors};
}

// Executed in an isolated browser realm. Only metadata leaves the frame.
async function frameStorage(includeCookies) {
  const result = {};
  async function read(type, fn) {
    try { result[type] = await fn(); } catch { result[type] = null; }
  }
  for (const [type,property] of [['local_storage','localStorage'],['session_storage','sessionStorage']]) {
    await read(type, () => {
      const store = window[property], rows = [];
      for (let i=0;i<store.length;i++) {
        const name = store.key(i);
        if (name!==null) rows.push({name,value_length:store.getItem(name)?.length??null});
      }
      return rows;
    });
  }
  await read('indexed_db',async () => {
    const rows=[];
    for (const {name,version} of await indexedDB.databases()) {
      const db = await new Promise((ok,fail) => {
        const request = indexedDB.open(name,version);
        request.onupgradeneeded = () => request.transaction.abort();
        request.onblocked = request.onerror = () => fail(Error());
        request.onsuccess = () => ok(request.result);
      });
      try {
        const object_stores = await Promise.all(Array.from(db.objectStoreNames,store=>new Promise((ok,fail)=>{
          const request=db.transaction(store,'readonly').objectStore(store).count();
          request.onsuccess=()=>ok({name:store,record_count:request.result});
          request.onerror=()=>fail(Error());
        })));
        rows.push({name,object_stores});
      } finally { db.close(); }
    }
    return rows;
  });
  await read('service_workers',async () => (await navigator.serviceWorker.getRegistrations()).map(r=>({scope:r.scope})));
  await read('cache_storage',async () => (await caches.keys()).map(name=>({name,size_bytes:null})));
  let visibleCookies=null;
  if (includeCookies) {
    try {
      visibleCookies=document.cookie.split(/; */).filter(Boolean).map(pair=>{
        const split=pair.indexOf('=');
        return {name:pair.slice(0,split),value_length:new TextEncoder().encode(pair.slice(split+1)).length};
      });
    } catch { /* Access can be disabled for this frame. */ }
  }
  return JSON.stringify({origin:location.origin,result,visibleCookies});
}

function consume(data, tab, top, identity, seen, add, label, observed, errors) {
  for (const [type,rows] of Object.entries(data.result)) {
    if (!rows) { errors(type,'frame_storage_unavailable'); continue; }
    // Deduplicate only within a known partition. Separate tab session stores.
    const key=JSON.stringify([type,identity,type==='session_storage'?tab:null]);
    if (seen.has(key)) continue;
    seen.add(key);
    observed.add(type);
    const crossSite=typeof identity==='string' && /\^(?:0|31$|4)/.test(identity);
    const partition=typeof identity==='string' ? identity.match(/\^0(https?:\/\/[^\^]+)$/)?.[1] : null;
    for (const r of rows) {
      const row={origin:label(data.origin),name:label(r.name),partition_key:label(partition),
        party_type:top?'first_party':crossSite?'third_party':null};
      if (type==='session_storage') Object.assign(row,{tab_index:tab,persistent:false});
      if ('value_length' in r) row.value_length=r.value_length;
      if (r.object_stores) row.object_stores=r.object_stores.map(s=>({name:label(s.name),record_count:s.record_count}));
      if ('scope' in r) row.scope=label(r.scope);
      if ('size_bytes' in r) row.size_bytes=r.size_bytes;
      add(type,row);
    }
  }
}

function flatten(node, childField) {
  return [node,...(node[childField]??[]).flatMap(child=>flatten(child,childField))];
}
const expression='('+frameStorage.toString()+')()';

async function collectTabs(client,add,label,observed,errors) {
  const {targetInfos}=await client.call('Target.getTargets');
  const {browserContextIds}=await client.call('Target.getBrowserContexts');
  const seen=new Set();
  let tab=0;
  for (const target of targetInfos.filter(t=>t.type==='page' && !browserContextIds.includes(t.browserContextId))) {
    tab++;
    let sessionId;
    try {
      ({sessionId}=await client.call('Target.attachToTarget',{targetId:target.targetId,flatten:true}));
      const call=(method,params)=>client.call(method,params,sessionId);
      const {frameTree}=await call('Page.getFrameTree');
      for (const {frame} of flatten(frameTree,'childFrames')) {
        if (!/^https?:/.test(frame.securityOrigin)) continue;
        try {
          const {storageKey}=await call('Storage.getStorageKeyForFrame',{frameId:frame.id});
          const {executionContextId}=await call('Page.createIsolatedWorld',{frameId:frame.id,worldName:'BSI audit'});
          const {result}=await call('Runtime.evaluate',{expression,contextId:executionContextId,awaitPromise:true,returnByValue:true});
          consume(JSON.parse(result.value),tab,frame.id===frameTree.frame.id,storageKey,seen,add,label,observed,errors);
        } catch { for (const t of types.slice(1)) errors(t,'frame_unavailable'); }
      }
    } catch { for (const t of types.slice(1)) errors(t,'tab_unavailable'); }
    finally { if (sessionId) await client.call('Target.detachFromTarget',{sessionId}).catch(()=>{}); }
  }
  for (const t of types.slice(1)) errors(t,observed.has(t)?'open_frames_only':'no_accessible_frames');
}

async function mullvadTabs(client,add,label,observed,errors) {
  const {contexts}=await client.call('browsingContext.getTree');
  const seen=new Set(), cookieKeys=new Set();
  let tab=0;
  for (const root of contexts) {
    tab++;
    for (const frame of flatten(root,'children')) {
      if (!/^https?:/.test(frame.url)) continue;
      const context=frame.context;
      let partition=null;
      let hasProtocolCookies=false;
      try {
        const {cookies,partitionKey}=await client.call('storage.getCookies',{partition:{type:'context',context}});
        partition=partitionKey;
        hasProtocolCookies=cookies.length>0;
        for (const c of cookies) {
          const key=JSON.stringify([partitionKey,c.domain,c.path,c.name]);
          if (cookieKeys.has(key)) continue;
          cookieKeys.add(key);
          const data=c.value;
          add('cookies',{name:label(c.name),domain:label(c.domain),path:label(c.path),
            persistent:c.expiry!==undefined,expires_at:c.expiry===undefined?null:new Date(c.expiry*1000).toISOString(),
            partition_key:null,http_only:c.httpOnly,secure:c.secure,same_site:c.sameSite??null,
            value_length:Buffer.from(data.value,data.type==='base64'?'base64':'utf8').length});
        }
        observed.add('cookies');
      } catch { errors('cookies','partition_unavailable'); }
      try {
        const response=await client.call('script.evaluate',{expression:'('+frameStorage.toString()+')(true)',target:{context,sandbox:'BSI audit'},awaitPromise:true});
        const data=JSON.parse(response.result.value);
        if (!hasProtocolCookies && data.visibleCookies!==null) {
          const key=JSON.stringify(['visible',root.userContext,new URL(root.url).origin,data.origin,new URL(frame.url).pathname]);
          if (!seen.has(key)) {
            seen.add(key);
            for (const cookie of data.visibleCookies) add('cookies',{origin:label(data.origin),name:label(cookie.name),
              party_type:root===frame?'first_party':null,http_only:false,value_length:cookie.value_length});
          }
          observed.add('cookies');
        }
        consume(data,tab,root===frame,[partition??context,root.userContext,new URL(root.url).origin,data.origin],seen,add,label,observed,errors);
      } catch { for (const t of types.slice(1)) errors(t,'frame_unavailable'); }
    }
  }
  errors('cookies','private_httponly_visibility_unverified');
  for (const t of types) errors(t,observed.has(t)?'open_contexts_only':'no_accessible_contexts');
}

function firefoxCookies(profile,add,label) {
  const file=join(profile,'cookies.sqlite');
  if (!existsSync(file)) throw Error();
  const {user_version,rows}=readStable(file,db=>{
    const {user_version}=db.prepare('PRAGMA user_version').get();
    const rows=db.prepare('SELECT name,host,path,length(CAST(value AS BLOB)) AS n,isSecure,isHttpOnly,expiry,sameSite,originAttributes FROM moz_cookies').all();
    return {user_version,rows};
  });
    for (const c of rows) {
      const attributes=new URLSearchParams(c.originAttributes.replace(/^\^/,''));
      add('cookies',{name:label(c.name),domain:label(c.host),path:label(c.path),value_length:c.n,
        partition_key:label(attributes.get('partitionKey')||attributes.get('firstPartyDomain')),
        secure:!!c.isSecure,http_only:!!c.isHttpOnly,persistent:true,
        expires_at:new Date(c.expiry*(user_version>=16?1:1000)).toISOString(),same_site:({0:'None',1:'Lax',2:'Strict'})[c.sameSite]??null});
    }
}

function readStable(file,query) {
  const check=()=>{
    if (['-wal','-journal'].some(s=>existsSync(file+s)&&statSync(file+s).size)) throw Error();
    const s=statSync(file,{bigint:true});
    return [s.ino,s.size,s.ctimeNs].join('/');
  };
  const before=check();
  const db=new DatabaseSync(pathToFileURL(file).href+'?mode=ro&immutable=1',{readOnly:true});
  try {
    db.exec('PRAGMA trusted_schema=OFF');
    const rows=query(db);
    if (before!==check()) throw Error();
    return rows;
  } finally { db.close(); }
}
