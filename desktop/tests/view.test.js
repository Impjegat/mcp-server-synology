// What the control window shows for each status. Run with: node --test desktop/tests/
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const View = require('../ui/view.js');

const base = {
  phase: 'stopped', stage: null, message: '', external: false, attention: null,
  account: 'BERNARD-PC\\synbroker', start_command: 'C:\\SynologyBroker\\start-broker.cmd',
  broker_url: 'https://localhost:8444', config_error: null,
  cert_untrusted: false, window_untrusted: false, can_trust: false,
  outdated: false, can_update: false, update_pending: false,
};
const status = (changes) => ({ ...base, ...changes });
const running = (changes) => status({ phase: 'running', ...changes });
const ids = (list) => list.map((notice) => notice.id);

test('the account is named the way the password label says it', () => {
  assert.equal(View.accountName('BERNARD-PC\\synbroker'), 'Synbroker');
  assert.equal(View.accountName('synbroker'), 'Synbroker');
  assert.equal(View.accountName('.\\svc_broker'), 'Svc_broker');
  // A name that is not a plain lower-case word is shown as it is written.
  assert.equal(View.accountName('broker@example.com'), 'broker@example.com');
  assert.equal(View.accountName('PC\\NasBroker'), 'NasBroker');
  assert.equal(View.accountName(''), 'broker');
});

test('a stopped app shows the password box, the Start button and nothing else', () => {
  const view = View.view(status({}));
  assert.equal(view.panel, 'start');
  assert.deepEqual(view.pill, { text: 'Stopped', kind: 'stopped' });
  assert.equal(view.passwordLabel, 'Windows password for the Synbroker account');
  assert.equal(view.startLabel, 'Start Broker');
  assert.equal(view.canStart, true);
  assert.deepEqual(View.notices(status({}), ''), []);
});

test('the command and account are a hint on the label, not text on the page', () => {
  const view = View.view(status({}));
  assert.equal(view.passwordHint, 'Starts C:\\SynologyBroker\\start-broker.cmd as BERNARD-PC\\synbroker');
});

test('while starting there is a progress bar and no way to type or press Start', () => {
  for (const stage of ['updating', 'launching', 'waiting']) {
    const view = View.view(status({ phase: 'starting', stage }));
    assert.equal(view.panel, 'progress', stage);
    assert.equal(view.canStart, false, stage);
  }
  assert.equal(View.view(status({ phase: 'starting', stage: 'waiting' })).pill.text, 'Starting');
  assert.equal(View.view(status({ phase: 'starting', stage: 'updating' })).pill.text, 'Updating');
  assert.equal(View.view(status({ phase: 'starting', stage: 'updating' })).progressLabel, 'Updating the broker');
});

test('the bar only rises and never reaches the end before the broker answers', () => {
  let shown = 0;
  for (const stage of ['updating', 'launching', 'waiting']) {
    for (let ms = 0; ms <= 600000; ms += 250) {
      const value = View.progress(stage, ms, shown);
      assert.ok(value >= shown, `${stage} at ${ms} ms went back from ${shown} to ${value}`);
      assert.ok(value <= 99, `${stage} at ${ms} ms claimed ${value}`);
      shown = value;
    }
  }
  assert.ok(shown >= 95, `a long wait still shows ${shown}`);
});

test('the bar moves at once and each stage starts further along than the last', () => {
  assert.ok(View.progress('launching', 0, 0) > 0);
  assert.ok(View.progress('waiting', 0, 0) > View.progress('launching', 0, 0));
  assert.ok(View.progress('launching', 500, 0) > View.progress('launching', 0, 0));
  // An unknown stage is treated as the first one, not as an error.
  assert.equal(View.progress(undefined, 0, 0), View.progress('launching', 0, 0));
  assert.equal(View.progress('waiting', -5, 0), View.progress('waiting', 0, 0));
});

test('a running broker shows its buttons, with Settings among them', () => {
  const view = View.view(running({}));
  assert.equal(view.panel, 'running');
  assert.deepEqual(view.pill, { text: 'Running', kind: 'running' });
  assert.deepEqual(view.buttons, { open: true, loginAll: true, settings: true, log: true, stop: true });
});

test('a client waiting for a sign-in shows in the pill', () => {
  const waiting = { waiting: 1, connected: 0, sessions_ending_soon: 0, grants_ending_soon: 0 };
  assert.deepEqual(View.view(running({ attention: waiting })).pill, { text: 'Waiting for you', kind: 'attention' });
  assert.equal(View.view(running({ attention: { ...waiting, waiting: 0 } })).pill.text, 'Running');
});

test('until Windows trusts the certificate no page opens, and Trust is offered', () => {
  const s = running({ window_untrusted: true, can_trust: true });
  const view = View.view(s);
  assert.deepEqual(view.buttons, { open: false, loginAll: false, settings: false, log: false, stop: true });
  const [notice] = View.notices(s, '');
  assert.equal(notice.id, 'trust');
  assert.equal(notice.kind, 'warn');
  assert.deepEqual(notice.action, { label: 'Trust certificate', command: 'trust_certificate' });
});

test('a certificate nothing vouches for is explained and cannot be trusted from here', () => {
  const s = running({ cert_untrusted: true, window_untrusted: true });
  assert.deepEqual(ids(View.notices(s, '')), ['cert']);
  assert.equal(View.notices(s, '')[0].action, undefined);
  assert.match(View.notices(s, '')[0].text, /ca_file/);
});

test('with no ca_file loaded the trust notice has no button', () => {
  const [notice] = View.notices(running({ window_untrusted: true, can_trust: false }), '');
  assert.equal(notice.id, 'trust');
  assert.equal(notice.action, null);
});

test('an older broker keeps its dashboard but not the pages it lacks, and offers Update', () => {
  const s = running({ outdated: true, can_update: true });
  assert.deepEqual(View.view(s).buttons, { open: true, loginAll: false, settings: false, log: false, stop: true });
  const [notice] = View.notices(s, '');
  assert.equal(notice.id, 'outdated');
  assert.deepEqual(notice.action, { label: 'Update Broker', command: 'prepare_update' });
  assert.equal(View.notices(running({ outdated: true, can_update: false }), '')[0].action, null);
});

test('a pending update changes what the Start button says', () => {
  assert.equal(View.view(status({ update_pending: true })).startLabel, 'Update and Start Broker');
});

test('a broker started elsewhere cannot be stopped from here, and the app says why', () => {
  const s = running({ external: true });
  assert.equal(View.view(s).buttons.stop, false);
  assert.deepEqual(ids(View.notices(s, '')), ['external']);
});

test('a failed start is a red notice; a settings file problem also blocks Start', () => {
  const failed = status({ phase: 'error', message: 'Windows did not accept that password.' });
  assert.equal(View.view(failed).panel, 'start');
  assert.equal(View.view(failed).canStart, true);
  assert.deepEqual(View.notices(failed, ''), [{
    id: 'message', kind: 'error', text: 'Windows did not accept that password.',
    key: 'message\nWindows did not accept that password.',
  }]);
  const broken = status({ config_error: 'synology-broker-app.json is not valid' });
  assert.equal(View.view(broken).canStart, false);
  assert.equal(View.notices(broken, '')[0].kind, 'error');
});

test('a message that is not a failure is a warning, and a refusal is shown too', () => {
  assert.equal(View.notices(status({ message: 'The broker stopped by itself.' }), '')[0].kind, 'warn');
  assert.deepEqual(ids(View.notices(status({}), 'Not allowed.')), ['local']);
});

test('several causes give several notices', () => {
  const s = running({ window_untrusted: true, can_trust: true, outdated: true, can_update: true, external: true });
  assert.deepEqual(ids(View.notices(s, '')), ['trust', 'outdated', 'external']);
});

test('a dismissed notice stays away until its cause goes and comes back', () => {
  const s = running({ window_untrusted: true, can_trust: true, outdated: true });
  const all = View.notices(s, '');
  let dismissed = new Set([all[0].key]);
  assert.deepEqual(ids(View.visible(all, dismissed)), ['outdated']);

  // Still the cause: the dismissal is kept.
  dismissed = View.reconcile(dismissed, View.notices(s, ''));
  assert.equal(dismissed.size, 1);

  // The cause went away: the dismissal is forgotten...
  const trusted = View.notices(running({ outdated: true }), '');
  dismissed = View.reconcile(dismissed, trusted);
  assert.equal(dismissed.size, 0);

  // ...so the notice shows again if the cause returns.
  assert.deepEqual(ids(View.visible(View.notices(s, ''), dismissed)), ['trust', 'outdated']);
});

test('a notice with new wording is a new notice', () => {
  const first = View.notices(status({ phase: 'error', message: 'First failure.' }), '');
  const dismissed = new Set([first[0].key]);
  const second = View.notices(status({ phase: 'error', message: 'Second failure.' }), '');
  assert.deepEqual(ids(View.visible(second, dismissed)), ['message']);
});

test('the page itself has only what was asked for', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'ui', 'index.html'), 'utf8');
  const body = html.slice(html.indexOf('<body>'));
  const text = body.replace(/<[^>]+>/g, '\n').split('\n').map((line) => line.trim()).filter(Boolean);
  assert.deepEqual(text, [
    'Synology Broker', 'Stopped',
    'Windows password for the Synbroker account', 'Start Broker',
    'Open Broker', 'Sign in all clients', 'Settings', 'Log', 'Stop Broker',
  ]);
  assert.doesNotMatch(html, /quit|footer|tray|browser/i);
  // The running panel and the progress bar are hidden until they apply.
  assert.match(html, /<section id="progress-panel" hidden>/);
  assert.match(html, /<section id="running-panel" hidden>/);
  // The notices come last, so they sit at the bottom of the window.
  assert.ok(body.indexOf('id="notices"') > body.indexOf('id="running-panel"'));
});

test('the window script calls only commands the app has', () => {
  const dir = path.join(__dirname, '..');
  const used = new Set();
  for (const file of ['ui/app.js', 'ui/view.js']) {
    const source = fs.readFileSync(path.join(dir, file), 'utf8');
    for (const match of source.matchAll(/(?:invoke|call)\('([a-z_]+)'|command: '([a-z_]+)'/g)) {
      used.add(match[1] || match[2]);
    }
  }
  const granted = JSON.parse(fs.readFileSync(path.join(dir, 'src-tauri/capabilities/default.json'), 'utf8'))
    .permissions.filter((name) => name.startsWith('allow-'))
    .map((name) => name.slice('allow-'.length).replaceAll('-', '_'));
  assert.deepEqual([...used].sort(), [...granted].sort());
});
