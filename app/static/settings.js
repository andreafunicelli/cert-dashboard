/* Approved settings-only enhancement. Never submits or intercepts a submission. */
(() => {
  'use strict';
  const prefix = 'cert-dashboard:settings-draft:v1:';
  const baselines = new Map();
  let panel;
  let sections = [];
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
    dirty = false;
    const visibleDrafts = new Map();
    for (const section of sections) {
      const baseline = baselines.get(section.tab);
      const draft = {};
      const initial = {};
      let sectionDirty = false;
      for (const field of section.controls) {
        const changed = valueOf(field) !== baseline[field.name];
        sectionDirty ||= changed;
        field.classList.toggle('is-dirty', changed);
        const marker = field.closest('.settings-field')?.querySelector('.field-change');
        if (marker) marker.hidden = !changed;
        if (persistable(field)) initial[field.name] = baseline[field.name];
        if (changed && persistable(field)) draft[field.name] = valueOf(field);
      }
      // Secret presence is only an in-memory dirty flag: never read it into a
      // baseline, draft, storage payload or rendered message.
      for (const field of section.secretControls) {
        const changed = Boolean(field.value);
        sectionDirty ||= changed;
        field.classList.toggle('is-dirty', changed);
      }
      dirty ||= sectionDirty;
      visibleDrafts.set(section.tab, sectionDirty);
      const key = prefix + section.tab;
      if (Object.keys(draft).length) storage('setItem', key, JSON.stringify({initial, values: draft}));
      else storage('removeItem', key);
    }
    for (const marker of document.querySelectorAll('[data-settings-tab-draft]')) {
      const tab = marker.dataset.settingsTabDraft;
      marker.hidden = visibleDrafts.has(tab) ? !visibleDrafts.get(tab) : !storage('getItem', prefix + tab);
    }
    const status = panel.querySelector('#settings-draft-status');
    if (status) status.textContent = !storageAvailable
      ? 'Draft storage is unavailable. Save before switching sections; unsaved values cannot be restored.'
      : dirty ? 'Unsaved changes. Non-secret drafts are kept in this browser tab; secrets, file selections and repository URLs are not retained. Save each changed section to apply.'
      : 'No unsaved changes in this tab.';
  }
  function initialize() {
    const next = document.querySelector('#settings-panel');
    if (!next || next === panel) return;
    panel = next;
    leavingForTab = false;
    const grouped = Array.from(panel.querySelectorAll('[data-settings-section]')).filter(section => section.dataset?.settingsSection);
    sections = (grouped.length ? grouped : [panel]).map(element => ({
      element, tab: element.dataset.tab,
      controls: Array.from(element.querySelectorAll('[data-settings-draft] input, [data-settings-draft] select, [data-settings-draft] textarea')).filter(eligible),
      secretControls: Array.from(element.querySelectorAll('[data-settings-secret]'))
    }));
    for (const section of sections) {
      const {element, tab, controls} = section;
      const key = prefix + tab;
      if (element.dataset.settingsSaved === 'true') {
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
      if (draft?.values && typeof draft.values === 'object' && element.dataset.settingsErrors !== 'true') {
        for (const field of controls) {
          if (!persistable(field) || !Object.hasOwn(draft.values, field.name)) continue;
          const value = draft.values[field.name];
          if (field.type === 'checkbox' && typeof value === 'boolean') field.checked = value;
          else if (field.type !== 'checkbox' && typeof value === 'string') field.value = value;
        }
      }
    }
    update();
  }
  const changed = event => { if (sections.some(section => section.controls.includes(event.target) || section.secretControls.includes(event.target))) update(); };
  document.addEventListener('input', changed);
  document.addEventListener('change', changed);
  // Observe the completed dispatch: HTMX (or another cancelled submit) prevents native
  // navigation. Keep its unload guard even if the request fails without a panel swap.
  // Never prevent, delay, rewrite or trigger the submission itself.
  document.addEventListener('submit', event => {
    queueMicrotask(() => { if (!event.defaultPrevented) leavingForTab = true; });
  });
  document.addEventListener('htmx:afterSwap', initialize);
  window.addEventListener('pageshow', () => { leavingForTab = false; initialize(); });
  document.addEventListener('click', event => {
    const link = event.target.closest('.tabs a');
    if (!link || !dirty || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const message = storageAvailable
      ? 'This tab has unsaved changes. Switch sections and keep the non-secret draft? Secret edits, file selections and repository URL edits will be lost. Cancel to stay and save them.'
      : 'Draft storage is unavailable. Switch sections and discard unsaved changes? Cancel to stay and save them.';
    if (!window.confirm(message)) event.preventDefault();
    else leavingForTab = true;
  });
  window.addEventListener('beforeunload', event => {
    if (!dirty || leavingForTab) return;
    event.preventDefault();
    event.returnValue = '';
  });
  initialize();
})();
