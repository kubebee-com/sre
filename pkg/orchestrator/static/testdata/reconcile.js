const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
class Element{constructor(tag,text){this.tag=tag;this.textContent=text||'';this.children=[];this.listeners={};this.disabled=false;}append(...v){this.children.push(...v);}replaceChildren(...v){this.children=v;}addEventListener(k,f){this.listeners[k]=f;}setAttribute(){}}
const host=new Element('section'),requests=[],scope={organization_id:'org',cluster_id:'cluster',application_id:'app'};
let age=180000,caps=['approve'];
const action=()=>({state:'SUBMITTED',hash:'exact-hash',submitted_at:new Date(Date.now()-age).toISOString(),plan:{id:'action',incident_id:'incident',kind:'REPLACE_POD',expires_at:new Date().toISOString()}});
const ctx={console,Date,URLSearchParams,generation:1,$:()=>host,node:(tag,text)=>new Element(tag,text),scopeQuery:s=>new URLSearchParams(s).toString(),status:()=>{},api:async(url,opts)=>{if(opts){requests.push({url,body:JSON.parse(opts.body)});return {}}if(url.startsWith('/api/capabilities'))return caps;if(url.startsWith('/api/actions'))return [action()];return []}};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(path.join(__dirname,'../orchestrator.js'),'utf8'),ctx);
const all=e=>[e,...e.children.flatMap(all)],button=()=>all(host).find(e=>e.tag==='button'&&e.textContent==='Record unresolved outcome');
async function main(){
 await ctx.refreshWorkflows(scope,'incident',1,[]);assert.ok(button(),'submitted action offers reconciliation');assert.ok(button().disabled,'explicit acknowledgment required');assert.ok(all(host).some(e=>/No automatic retry/.test(e.textContent)),'no retry message');
 let checkbox=all(host).find(e=>e.tag==='input'&&e.type==='checkbox');checkbox.checked=true;checkbox.listeners.change();assert.equal(button().disabled,false);await button().listeners.click();assert.equal(requests.length,1);assert.match(requests[0].url,/\/api\/actions\/action\/reconcile\?/);assert.equal(requests[0].body.hash,'exact-hash');assert.match(requests[0].url,/application_id=app/);
 age=119000;await ctx.refreshWorkflows(scope,'incident',1,[]);checkbox=all(host).find(e=>e.tag==='input'&&e.type==='checkbox');checkbox.checked=true;checkbox.listeners.change();assert.ok(button().disabled,'premature reconciliation unavailable');
 age=180000;caps=[];await ctx.refreshWorkflows(scope,'incident',1,[]);assert.equal(button(),undefined,'viewer cannot reconcile');
 caps=['approve'];await ctx.refreshWorkflows(scope,'incident',1,[]);checkbox=all(host).find(e=>e.tag==='input'&&e.type==='checkbox');checkbox.checked=true;checkbox.listeners.change();ctx.generation=2;await button().listeners.click();assert.equal(requests.length,1,'stale scope cannot reconcile');
 console.log('reconciliation UI contracts passed');
}
main().catch(e=>{console.error(e);process.exitCode=1});
