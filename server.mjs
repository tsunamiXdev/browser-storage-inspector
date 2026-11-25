import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { parseEnv } from 'node:util';
import { capture, stages } from './inspector.mjs';

const dir=dirname(fileURLToPath(import.meta.url));
const tool={name:'capture_storage_snapshot',description:'Export a private local browser storage metadata snapshot for the configured audit profile.',
  inputSchema:{type:'object',required:['browser'],properties:{
    browser:{type:'string',enum:['chrome','mullvad']},capture_stage:{type:'string',enum:stages,default:'manual'}
  },additionalProperties:false}};

async function dispatch(method,params) {
  if (method==='initialize') return {protocolVersion:'2025-06-18',serverInfo:{name:'browser-storage-inspector',version:'1.0.0'},capabilities:{tools:{}}};
  if (method==='ping') return {};
  if (method==='tools/list') return {tools:[tool]};
  if (method!=='tools/call') throw -32601;
  const a=params.arguments;
  if (params.name!==tool.name || !a || !['chrome','mullvad'].includes(a.browser) ||
      !stages.includes(a.capture_stage===undefined?'manual':a.capture_stage) ||
      Object.keys(a).some(k=>!['browser','capture_stage'].includes(k))) throw -32602;
  try {
    const file=join(dir,'.env');
    if ((statSync(file).mode & 0o077)!==0) throw Error();
    const config=parseEnv(readFileSync(file,'utf8'));
    const root=config[a.browser==='chrome'?'BSI_CHROME_USER_DATA_DIR':'BSI_MULLVAD_PROFILE_DIR'];
    if (!root) throw Error();
    const output=resolve(dir,config.BSI_OUTPUT_DIR||'snapshots');
    const result=await capture(a.capture_stage??'manual',{BSI_BROWSER:a.browser,BSI_USER_DATA_DIR:root,
      BSI_PROFILE_ID:a.browser,BSI_PUBLIC_LABELS:config.BSI_PUBLIC_LABELS,BSI_OUTPUT_DIR:output,
      protectedProfiles:[config.BSI_CHROME_USER_DATA_DIR,config.BSI_MULLVAD_PROFILE_DIR].filter(Boolean)});
    return {content:[{type:'text',text:JSON.stringify(result)}]};
  } catch {
    return {isError:true,content:[{type:'text',text:'Capture failed. Check the owner-only .env, selected profile, public labels and output directory.'}]};
  }
}
for await (const line of createInterface({input:process.stdin})) {
  let req,reply={jsonrpc:'2.0',id:null};
  try {
    try { req=JSON.parse(line); } catch { throw -32700; }
    if (req?.jsonrpc!=='2.0'||typeof req.method!=='string') throw -32600;
    if (!Object.hasOwn(req,'id')) continue;
    reply.id=req.id;
    reply.result=await dispatch(req.method,req.params??{});
  } catch (code) {
    reply.error={code:Number.isInteger(code)?code:-32603,message:({'-32601':'Method not found','-32602':'Invalid parameters','-32700':'Parse error'})[code]??'Invalid request'};
  }
  console.log(JSON.stringify(reply));
}
