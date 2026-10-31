/* Run: node --test tests/settings_drafts.test.cjs. No browser/dependency install. */
const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('app/static/settings.js', 'utf8');
const key = tab => 'cert-dashboard:settings-draft:v1:' + tab;
function field(name, value, type = 'text') {
  const classes = new Set();
  const marker = {hidden: true};
  return {name, value, type, checked: value, marker, classes,
    classList: {toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name)},
    closest: () => ({querySelector: () => marker})};
}
function panel(tab, fields, saved = false, errors = false) {
  const status = {textContent: ''};
  return {dataset: {tab, settingsSaved: String(saved), settingsErrors: String(errors)},
    querySelectorAll: () => fields, querySelector: () => status, status};
}
function harness(initialPanel, stored = new Map(), unavailable = false, tabMarkers = []) {
  let current = initialPanel;
  const events = {};
  const windowEvents = {};
  let accepted = false;
  const prompts = [];
  const storage = {};
  for (const action of ['getItem', 'setItem', 'removeItem']) storage[action] = (key, value) => {
    if (unavailable) throw Error('storage denied');
    if (action === 'getItem') return stored.get(key) ?? null;
    if (action === 'setItem') stored.set(key, value);
    else if (action === 'removeItem') stored.delete(key);
  };
  const document = {querySelector: () => current, querySelectorAll: () => tabMarkers, addEventListener: (name, fn) => { events[name] = fn; }};
  const window = {sessionStorage: storage, location: {href: 'https://example.test/settings?tab=smtp&saved=1'},
    history: {state: null, replaceState: (_state, _title, url) => { window.location.href = String(url); }},
    confirm: message => { prompts.push(message); return accepted; }, addEventListener: (name, fn) => { windowEvents[name] = fn; }};
  // Execute only the fixed repository asset, not user-provided source.
  vm.runInNewContext(source, {document, window, URL});
  return {stored, events, windowEvents, window, prompts,
    edit: (control, value) => { if (control.type === 'checkbox') control.checked = value; else control.value = value; events.input({target: control}); },
    swap: next => { current = next; events['htmx:afterSwap'](); },
    accept: value => { accepted = value; }};
}

test('text, select and checkbox edits mark dirty, reverting removes the draft', () => {
  const fields = [field('host', 'old'), field('security', 'starttls', 'select-one'), field('tls_verify', true, 'checkbox')];
  const h = harness(panel('smtp', fields));
  for (const [index, value] of [[0, 'new'], [1, 'ssl'], [2, false]]) {
    h.edit(fields[index], value);
    assert.equal(fields[index].marker.hidden, false);
    assert.ok(fields[index].classes.has('is-dirty'));
  }
  const saved = JSON.parse(h.stored.get(key('smtp')));
  assert.deepEqual(saved.values, {host: 'new', security: 'ssl', tls_verify: false});
  for (const [index, value] of [[0, 'old'], [1, 'starttls'], [2, true]]) h.edit(fields[index], value);
  assert.equal(h.stored.has(key('smtp')), false);
});

test('drafts restore per tab after a full navigation; saved success clears only its draft', () => {
  const host = field('host', 'old');
  const h = harness(panel('smtp', [host]));
  h.edit(host, 'new');
  h.stored.set(key('general'), JSON.stringify({initial: {timezone: 'UTC'}, values: {timezone: 'Europe/Rome'}}));
  const restored = field('host', 'old');
  harness(panel('smtp', [restored]), h.stored);
  assert.equal(restored.value, 'new');
  assert.equal(restored.marker.hidden, false);
  const success = harness(panel('smtp', [field('host', 'new')], true), h.stored);
  assert.equal(h.stored.has(key('smtp')), false);
  assert.equal(h.stored.has(key('general')), true);
  assert.equal(new URL(success.window.location.href).searchParams.has('saved'), false);
  const markers = ['smtp', 'general'].map(tab => ({dataset: {settingsTabDraft: tab}, hidden: true}));
  harness(panel('smtp', [field('host', 'new')]), h.stored, false, markers);
  assert.equal(markers[0].hidden, true);
  assert.equal(markers[1].hidden, false);
});

test('422 never clears pending state or overwrites server-rendered invalid input', () => {
  const host = field('host', 'old');
  const h = harness(panel('smtp', [host]));
  h.edit(host, 'new');
  const refused = field('host', 'invalid');
  h.swap(panel('smtp', [refused], false, true));
  assert.equal(refused.value, 'invalid');
  assert.equal(refused.marker.hidden, false);
  const nativeRefusal = field('host', 'invalid');
  harness(panel('smtp', [nativeRefusal], false, true), h.stored);
  assert.equal(nativeRefusal.marker.hidden, false);
  assert.equal(JSON.parse(h.stored.get(key('smtp'))).values.host, 'invalid');
});

test('excluded secrets, hidden CSRF, files and credential-bearing URLs never enter storage', () => {
  const fields = [field('password', 'SECRET', 'password'), field('api_key', 'SECRET'), field('client_secret', 'SECRET'),
    field('access_token', 'SECRET'), field('csrf_token', 'SECRET', 'hidden'), field('file', 'SECRET', 'file'),
    field('repo_url', 'https://user:SECRET@example.test'), field('ref', 'main')];
  const h = harness(panel('inventory', fields));
  h.edit(fields[7], 'next');
  for (const value of h.stored.values()) assert.equal(value.includes('SECRET'), false);
  for (const control of fields.slice(0, 6)) assert.equal(control.marker.hidden, true);
  assert.equal(JSON.parse(h.stored.get(key('inventory'))).values.ref, 'next');
  assert.equal(JSON.parse(h.stored.get(key('inventory'))).initial.repo_url, undefined);
  assert.equal(h.events.submit, undefined);
});

test('tab changes confirm; cancelled navigation keeps edits; other exits warn before unloading', () => {
  const host = field('host', 'old');
  const h = harness(panel('smtp', [host]));
  h.edit(host, 'new');
  let prevented = false;
  const click = {target: {closest: () => ({})}, button: 0, preventDefault: () => { prevented = true; }};
  h.events.click(click);
  assert.ok(prevented);
  assert.match(h.prompts.at(-1), /keep the non-secret draft/);
  prevented = false;
  h.windowEvents.beforeunload({preventDefault: () => { prevented = true; }});
  assert.ok(prevented);
  h.accept(true);
  h.events.click(click);
  prevented = false;
  h.windowEvents.beforeunload({preventDefault: () => { prevented = true; }});
  assert.equal(prevented, false);
  h.windowEvents.pageshow();
  h.windowEvents.beforeunload({preventDefault: () => { prevented = true; }});
  assert.ok(prevented);
});

test('unavailable storage is visible, does not crash, and does not drop dirty indicators', () => {
  const host = field('host', 'old');
  const p = panel('smtp', [host]);
  const h = harness(p, new Map(), true);
  h.edit(host, 'new');
  assert.equal(host.marker.hidden, false);
  assert.match(p.status.textContent, /storage is unavailable/);
});

test('denied storage tab navigation warns of discard; cancel keeps edits and unload protection', () => {
  const host = field('host', 'old');
  const h = harness(panel('smtp', [host]), new Map(), true);
  h.edit(host, 'new');
  let prevented = false;
  const click = {target: {closest: () => ({})}, button: 0, preventDefault: () => { prevented = true; }};
  h.events.click(click);
  assert.match(h.prompts.at(-1), /storage is unavailable/i);
  assert.match(h.prompts.at(-1), /discard unsaved changes/i);
  assert.doesNotMatch(h.prompts.at(-1), /keep.*draft/i);
  assert.equal(prevented, true);
  assert.equal(host.value, 'new');
  assert.equal(host.marker.hidden, false);
  prevented = false;
  h.windowEvents.beforeunload({preventDefault: () => { prevented = true; }});
  assert.equal(prevented, true);
  h.accept(true);
  prevented = false;
  h.events.click(click);
  assert.equal(prevented, false);
  h.windowEvents.beforeunload({preventDefault: () => { prevented = true; }});
  assert.equal(prevented, false);
  assert.equal(h.stored.size, 0);
  h.windowEvents.pageshow();
  h.windowEvents.beforeunload({preventDefault: () => { prevented = true; }});
  assert.equal(prevented, true);
});
