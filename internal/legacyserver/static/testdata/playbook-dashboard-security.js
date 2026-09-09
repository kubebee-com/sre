'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.dataset = {}; this._text = ''; }
  set textContent(value) { this._text = String(value); }
  get textContent() { return this._text; }
  set innerHTML(_) { throw new Error('Untrusted dashboard content reached innerHTML'); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
}
const nodes = new Map();
const document = {
  readyState: 'loading',
  addEventListener() {},
  createElement(tag) { return new Element(tag); },
  getElementById(id) { if (!nodes.has(id)) nodes.set(id, new Element('div')); return nodes.get(id); }
};
const context = vm.createContext({document, Element, console});
const app = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
vm.runInContext(app, context);
const malicious = `</pre><img src=x onerror="alert(1)"><script>alert(2)</script>`;
context.payload = [{id: malicious, version: 1, lifecycle: 'REVIEW', title: malicious, summary: malicious, steps: [{description: malicious}], evidence: [{summary: malicious}], source_ids: [malicious]}];
vm.runInContext('renderPlaybookCatalog(payload)', context);
const visited = [];
function walk(node) { visited.push(node); for (const child of node.children) walk(child); }
walk(nodes.get('playbook-catalog'));
assert(visited.some(node => node.textContent === malicious));
assert(!visited.some(node => ['script', 'img', 'iframe'].includes(node.tagName)));
const actions = visited.filter(node => node.tagName === 'button');
assert.strictEqual(actions.length, 2);
assert(actions.every(node => node.dataset.playbookId === malicious && node.dataset.action === 'playbook-transition'));
context.status = {available: true, catalog: {}, tasks: {'playbook.digest': {calls: 1, errors: 0, token_usage: null}}, outcomes: {[malicious]: 1}, provider: malicious};
vm.runInContext('renderPlaybookStatus(status)', context);
assert(nodes.get('playbook-task-usage').children.some(node => node.textContent.includes('Unavailable')));
assert(nodes.get('playbook-provider').textContent.includes(malicious));
console.log('Playbook dashboard uses text nodes for untrusted content.');
