'use strict';
let scopes = [], selectedScope = null, incidentID = '', csrf = '', actorID = '', generation = 0;
const $ = id => document.getElementById(id);
function node(tag, text, className) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; }
function scopeQuery(scope) { return new URLSearchParams(scope).toString(); }
async function api(path, options = {}) {
  const response = await fetch(path, {credentials:'same-origin', ...options, headers:{'Content-Type':'application/json', 'X-SRE-CSRF':csrf, ...(options.headers || {})}});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request unavailable');
  return data;
}
function status(message, failed = false) { $('status').textContent = message; $('status').className = failed ? 'error' : ''; }
function clearIncident() { incidentID = ''; $('evidence').replaceChildren(); $('claims').replaceChildren(); $('incident-heading').replaceChildren(node('h2','Select an incident')); $('diagnose').hidden = true; if($('workflows'))$('workflows').replaceChildren(); }
async function connect() {
  try {
    const session = await api('/api/session'); csrf = session.csrf || ''; actorID = session.principal.id;
    scopes = await api('/api/scopes');
    const setupScopes=await api('/api/setup-scopes');for(const scope of setupScopes)if(!scopes.some(s=>scopeQuery(s)===scopeQuery(scope)))scopes.push(scope); $('scope').replaceChildren(node('option','Select an application'));
    scopes.forEach((scope,index) => {const option=node('option',`${scope.organization_id} / ${scope.cluster_id} / ${scope.application_id}`);option.value=String(index);$('scope').append(option);});
    $('scope').selectedIndex=0;status(scopes.length ? 'Select your application scope.' : 'No application access is assigned to this identity.');
    const deepLink=new URLSearchParams(window.location.search),index=scopes.findIndex(s=>['organization_id','cluster_id','application_id'].every(k=>s[k]===deepLink.get(k)));
    if(index>=0){$('scope').selectedIndex=index+1;selectedScope=scopes[index];await refresh();const linked=deepLink.get('incident_id');if(linked)await loadIncident(linked,{...selectedScope});}

  } catch (error) { status('Sign in with your company identity to review investigations.', true); }
}
async function refresh() {
  const current = ++generation; clearIncident(); $('incidents').replaceChildren();if(typeof clearScopePanels==='function')clearScopePanels();
  if (!selectedScope) return;
  if(typeof refreshSetup==='function')refreshSetup({...selectedScope},current);
  if(typeof refreshLearning==='function')refreshLearning({...selectedScope},current);
  if(typeof refreshInbox==='function')refreshInbox({...selectedScope});
  if(typeof refreshOperations==='function')refreshOperations({...selectedScope});
  const scope = {...selectedScope}; status('Refreshing application incidents…');
  try {
    const incidents = await allPages('/api/incidents?',scope);
    if (current !== generation) return;
    incidents.forEach(incident => { const button=node('button',`${incident.id} · ${incident.state}`);button.addEventListener('click',()=>loadIncident(incident.id,scope));$('incidents').append(button); });
    if (!incidents.length) $('incidents').append(node('p','No incidents in this response. Check collector coverage before inferring health.'));
    status('Incident list refreshed.');
  } catch(error) { if(current===generation)status(error.message+' Previous selections were cleared.',true); }
}
async function loadIncident(id, scope) {
  const current=++generation; clearIncident(); incidentID=id; $('incident-heading').replaceChildren(node('h2',id));status('Loading evidence and conclusions…');
  try {
    const items=await allPages(`/api/incidents/${encodeURIComponent(id)}/items?`,scope);
    if(current!==generation)return;
    if(typeof refreshWorkflows==='function')refreshWorkflows(scope,id,current,items);
    const caps=await api('/api/capabilities?'+scopeQuery(scope));if(current!==generation)return;
    if(typeof refreshJobs==='function')refreshJobs(scope,id,current,caps);
    for(const view of items) (view.item.kind==='EVIDENCE'?$('evidence'):$('claims')).append(itemCard(view,scope,id,current,caps));
    if(!items.some(v=>v.item.kind==='EVIDENCE'))$('evidence').append(node('p','No observed evidence in this response.'));
    if(!items.some(v=>v.item.kind==='CLAIM'))$('claims').append(node('p','No diagnostic conclusions yet.'));
    status('Evidence and conclusions refreshed.');
    try { const profiles=await api('/api/profiles?'+scopeQuery(scope));if(current!==generation)return;$('profile').replaceChildren(...profiles.map(id=>{const o=node('option',id);o.value=id;return o;}));$('diagnose').hidden=profiles.length===0; } catch (_) { if(current===generation)$('diagnose').hidden=true; }
  } catch(error) { if(current===generation){clearIncident();status(error.message+' Refresh before acting.',true);} }
}
function itemCard(view,scope,id,current,caps=null) {
  const item=view.item, card=node('section',undefined,'card'), body=item.body || {},canFeedback=caps===null||caps.includes('feedback');
  const title=item.kind==='EVIDENCE' ? body.code || 'Observation' : body.assessment?.status || 'Conclusion';
  card.append(node('h3',title),node('p',`${item.id} · version ${item.version}`,'meta'),node('p',`Observed ${new Date(item.observed_at).toLocaleString()} · valid until ${new Date(item.valid_until).toLocaleString()}`,'meta'));
  if(!view.eligible)card.append(node('p','Not eligible for reuse. Check disputes, dependencies, and freshness.','notice'));
  if(item.kind==='CLAIM')card.append(node('p',body.assessment?.reason_code || 'Independent review required.','notice'));
  const details=node('details');details.append(node('summary','Evidence and diagnostic details'),node('pre',JSON.stringify(body,null,2)));card.append(details);
  const controls=node('div',undefined,'review'), reason=node('select');reason.setAttribute('aria-label','Optional feedback reason');
  for(const code of ['', 'FACTUAL_ERROR','NOT_APPLICABLE','STALE','MISSING_EVIDENCE','CONTRADICTED','CONFIRMED','UNRESOLVED']) {const option=node('option',code || 'Optional reason');option.value=code;reason.append(option);}
  const message=node('p','No assessment selected.','saved');message.setAttribute('role','status');message.setAttribute('aria-live','polite');
  let supersedes=(view.feedback || []).find(e=>e.actor_id===actorID)?.id || '', pending=null;
  const buttons=[];
  for(const [assessment,label] of [['TRUE','True'],['FALSE','False'],['CANNOT_VERIFY','Cannot verify']]) {
    const button=node('button',label);button.disabled=!canFeedback;button.setAttribute('aria-pressed','false');buttons.push(button);
    button.addEventListener('click',async()=>{
      if(current!==generation)return;
      const signature=assessment+'|'+reason.value;
      if(!pending || pending.signature!==signature)pending={signature,key:crypto.randomUUID()};
      buttons.forEach(b=>b.disabled=true);reason.disabled=true;message.textContent='Saving your assessment…';
      try {
        const event=await api(`/api/incidents/${encodeURIComponent(id)}/feedback?`+scopeQuery(scope),{method:'POST',body:JSON.stringify({incident_id:id,item:{id:item.id,version:item.version},item_hash:item.hash,assessment,reason_code:reason.value,idempotency_key:pending.key,supersedes})});
        if(current!==generation)return;
        supersedes=event.id;pending=null;buttons.forEach(b=>b.setAttribute('aria-pressed',String(b===button)));
        message.textContent=assessment==='FALSE'?'Saved. This item and dependent conclusions are quarantined.':'Saved as attributed feedback; independent review determines diagnostic correctness.';
        history.prepend(node('p',`${label} · ${event.actor_id} · ${new Date(event.at).toLocaleString()}`));
        if(assessment==='FALSE'){await loadIncident(id,scope);if(typeof refreshOperations==='function')refreshOperations(scope);if(typeof refreshLearning==='function')refreshLearning(scope,generation);}
      } catch(error) {if(current===generation){message.textContent=error.message;message.className='error';}}
      finally {if(current===generation){buttons.forEach(b=>b.disabled=!canFeedback);reason.disabled=!canFeedback;}}
    });controls.append(button);
  }
  reason.disabled=!canFeedback;const own=(view.feedback||[]).find(e=>e.actor_id===actorID);if(own){const index=['TRUE','FALSE','CANNOT_VERIFY'].indexOf(own.assessment);if(index>=0)buttons[index].setAttribute('aria-pressed','true');message.textContent='Your saved assessment: '+own.assessment;}controls.append(reason);card.append(node('small','Assess this exact item. True does not automatically promote it to trusted knowledge.'),controls,message);
  const history=node('details');history.append(node('summary','Engineer feedback history'));
  for(const event of view.feedback || [])history.append(node('p',`${event.assessment} · ${event.actor_id} · ${new Date(event.at).toLocaleString()}${event.reason_code?' · '+event.reason_code:''}`));
  card.append(history);if(typeof addStewardReview==='function')addStewardReview(card,view,scope,id,current,caps||[]);return card;
}
$('scope').addEventListener('change',()=>{selectedScope=$('scope').selectedIndex>0?scopes[Number($('scope').value)]:null;refresh();});
$('refresh').addEventListener('click',()=>refresh());
$('investigate').addEventListener('click',async()=>{if(!selectedScope||!incidentID)return;const current=generation,scope={...selectedScope},id=incidentID;$('investigate').disabled=true;status('Investigating current eligible evidence…');try{await api(`/api/incidents/${encodeURIComponent(id)}/investigate?`+scopeQuery(scope),{method:'POST',body:JSON.stringify({profile_id:$('profile').value})});if(current===generation)await loadIncident(id,scope);}catch(error){if(current===generation)status(error.message,true);}finally{$('investigate').disabled=false;}});
connect();
