const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.attributes={};this.textContent='';this.value='';}
 set innerHTML(_){throw new Error('untrusted HTML sink used');}
 append(...children){this.children.push(...children);} prepend(...children){this.children.unshift(...children);} replaceChildren(...children){this.children=[...children];}
 setAttribute(key,value){this.attributes[key]=value;} addEventListener(event,listener){this.listeners[event]=listener;}
}
const elements=new Map(),element=id=>{if(!elements.has(id))elements.set(id,new Element('div'));return elements.get(id)};
const context={console,URLSearchParams,Date,crypto:{randomUUID:()=> 'unique-request'},document:{getElementById:element,createElement:tag=>new Element(tag)},fetch:async path=>({ok:true,json:async()=>path==='/api/session'?{principal:{id:'me'},csrf:'csrf'}:[]})};
vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../app.js'),'utf8'),context);
async function main(){await new Promise(setImmediate);vm.runInContext('generation=1;actorID="me"',context);
 const scope={organization_id:'org',cluster_id:'cluster',application_id:'app'},view={eligible:true,item:{id:'evidence',version:2,hash:'hash',kind:'EVIDENCE',observed_at:new Date().toISOString(),valid_until:new Date().toISOString(),body:{code:'<img src=x onerror=alert(1)>'}},feedback:[]};
 const card=context.itemCard(view,scope,'incident',1),controls=card.children.find(c=>c.className==='review'),buttons=controls.children.filter(c=>c.tag==='button');
 assert.deepEqual(buttons.map(b=>b.textContent),['True','False','Cannot verify']);assert.ok(buttons.every(b=>b.attributes['aria-pressed']==='false'),'no default positive assessment');
 const requests=[];context.fetch=async(path,options)=>{if(!options.body)return {ok:true,json:async()=>[]};requests.push({path,body:JSON.parse(options.body)});return {ok:true,json:async()=>({id:'event',actor_id:'me',at:new Date().toISOString()})}};
 await buttons[1].listeners.click();assert.equal(requests[0].body.assessment,'FALSE');assert.equal(requests[0].body.item.version,2);assert.equal(requests[0].body.item_hash,'hash');assert.match(requests[0].path,/cluster_id=cluster/);assert.equal(buttons[1].attributes['aria-pressed'],'true');assert.ok(card.children.some(c=>/quarantined/.test(c.textContent)));
 vm.runInContext('generation=1',context);context.fetch=async()=>({ok:false,json:async()=>({error:'state changed; refresh'})});await buttons[0].listeners.click();assert.ok(card.children.some(c=>/state changed/.test(c.textContent)));assert.equal(buttons[0].attributes['aria-pressed'],'false');assert.ok(buttons.every(b=>!b.disabled));
 vm.runInContext('generation=2',context);await buttons[2].listeners.click();assert.equal(requests.length,1,'stale scope card cannot send feedback');
 console.log('enterprise feedback UI contracts passed');
}
main().catch(error=>{console.error(error);process.exitCode=1});
