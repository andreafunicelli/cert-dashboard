/* Approved settings-only enhancement. Never submits or handles a submit event. */
(() => {
  'use strict';
  const prefix = 'cert-dashboard:settings-draft:v1:';
  const baselines = new Map();
  let panel;
  let controls = [];
  let dirty = false;
  let storageAvailable = true;
  let leavingForTab = false;
  const valueOf = field => field.type === 'checkbox' ? field.checked : field.value;
  const eligible = field => field.name && !/secret|key|token/i.test(field.name)
    && !['password', 'hidden', 'file', 'submit', 'button'].includes(field.type);
  // Even an invalid repository URL can contain credentials. Never persist it.
  const persistable = field => field.name !== 'repo_url';
  function storage(action, key, value) {
    try { return window.sessionStorage[action](key, value); }
    catch (_) { storageAvailable = false; return null; }
  }
  function update() {
    if (!panel) return;
    const baseline = baselines.get(panel.dataset.tab);
    const draft = {};
    const initial = {};
    dirty = false;
    for (const field of controls) {
      const changed = valueOf(field) !== baseline[field.name];
      dirty ||= changed;
      field.classList.toggle('is-dirty', changed);
      const marker = field.closest('.settings-field')?.querySelector('.field-change');
      if (marker) marker.hidden = !changed;
      if (persistable(field)) initial[field.name] = baseline[field.name];
      if (changed && persistable(field)) draft[field.name] = valueOf(field);
    }
    const key = prefix + panel.dataset.tab;
    if (Object.keys(draft).length) storage('setItem', key, JSON.stringify({initial, values: draft}));
    else storage('removeItem', key);
    for (const marker of document.querySelectorAll('[data-settings-tab-draft]')) {
      marker.hidden = marker.dataset.settingsTabDraft === panel.dataset.tab ? !dirty
        : !storage('getItem', prefix + marker.dataset.settingsTabDraft);
    }
    const status = panel.querySelector('#settings-draft-status');
    if (status) status.textContent = !storageAvailable
      ? 'Draft storage is unavailable. Save before switching sections; unsaved values cannot be restored.'
      : dirty ? 'Unsaved changes. Non-secret drafts are kept in this browser tab; repository URLs are not retained. Save to apply.'
      : 'No unsaved changes in this section.';
  }
  function initialize() {
    const next = document.querySelector('#settings-panel');
    if (!next || next === panel) return;
    panel = next;
    leavingForTab = false;
    controls = Array.from(panel.querySelectorAll('[data-settings-draft] input, [data-settings-draft] select, [data-settings-draft] textarea')).filter(eligible);
    const tab = panel.dataset.tab;
    const key = prefix + tab;
    if (panel.dataset.settingsSaved === 'true') {
      storage('removeItem', key);
      baselines.delete(tab);
      // A later reload of this URL must not erase a new unsaved draft.
      const url = new URL(window.location.href);
      url.searchParams.delete('saved');
      window.history.replaceState(window.history.state, '', url);
    }
    let draft;
    try { draft = JSON.parse(storage('getItem', key) || '{}'); }
    catch (_) { storage('removeItem', key); draft = {}; }
    if (!baselines.has(tab)) {
      const initial = Object.fromEntries(controls.map(field => [field.name, valueOf(field)]));
      for (const field of controls) {
        if (persistable(field) && Object.hasOwn(draft?.initial || {}, field.name)
            && typeof draft.initial[field.name] === typeof valueOf(field)) initial[field.name] = draft.initial[field.name];
      }
      baselines.set(tab, initial);
    }
    if (draft?.values && typeof draft.values === 'object' && panel.dataset.settingsErrors !== 'true') {
      for (const field of controls) {
        if (!persistable(field) || !Object.hasOwn(draft.values, field.name)) continue;
        const value = draft.values[field.name];
        if (field.type === 'checkbox' && typeof value === 'boolean') field.checked = value;
        else if (field.type !== 'checkbox' && typeof value === 'string') field.value = value;
      }
    }
    update();
  }
  document.addEventListener('input', event => { if (controls.includes(event.target)) update(); });
  document.addEventListener('change', event => { if (controls.includes(event.target)) update(); });
  document.addEventListener('htmx:afterSwap', initialize);
  window.addEventListener('pageshow', () => { leavingForTab = false; initialize(); });
  document.addEventListener('click', event => {
    const link = event.target.closest('.tabs a');
    if (!link || !dirty || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const message = storageAvailable
      ? 'This section has unsaved changes. Switch sections and keep the non-secret draft? Repository URL edits will be lost.'
      : 'Draft storage is unavailable. Switch sections and discard unsaved changes? Cancel to stay and save them.';
    if (!window.confirm(message)) {
      event.preventDefault();
    } else {
      leavingForTab = true;
    }
  });
  window.addEventListener('beforeunload', event => {
    if (!dirty || leavingForTab) return;
    event.preventDefault();
    event.returnValue = '';
  });
  initialize();
})();
