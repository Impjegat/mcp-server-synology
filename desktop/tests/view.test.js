// What the app's window shows for each status. Run with: node --test desktop/tests/
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

test('a running broker asks for the passkey, and once it is given shows the sidebar and pages', () => {
  const waiting = View.view(running({}), false);
  assert.equal(waiting.panel, 'signin');
  assert.deepEqual(waiting.pill, { text: 'Running', kind: 'running' });
  assert.equal(waiting.pages, true);
  const inside = View.view(running({}), true);
  assert.equal(inside.panel, 'shell');
  assert.deepEqual(inside.nav, { home: true, settings: true, log: true });
  assert.equal(inside.canSignOut, true);
  // Before the broker answers there is no passkey to give, whatever the page says.
  assert.equal(View.view(status({ phase: 'starting', stage: 'waiting' }), true).panel, 'progress');
  assert.equal(View.view(status({}), true).panel, 'start');
});

test('the broker\'s page says by its title whether the passkey has been given', () => {
  for (const title of ['Sign in', 'Private sign-in', 'No owner enrolled', 'Enroll a passkey', 'about:blank', '', null, undefined]) {
    assert.equal(View.signedIn(title), false, String(title));
  }
  for (const title of ['Clients', 'Settings', 'Log', 'Synology broker']) {
    assert.equal(View.signedIn(title), true, title);
  }
});

test('the sidebar has three entries, and every path of the broker\'s belongs to one', () => {
  assert.equal(View.section('/'), '/');
  assert.equal(View.section('/settings'), '/settings');
  assert.equal(View.section('/log'), '/log');
  assert.equal(View.section('/login/abc123'), '/');
  assert.equal(View.section('/login-all'), '/');
  assert.equal(View.section('/anything/else'), '/');
});

test('Back and Forward walk the pages visited, and a new visit drops what was ahead', () => {
  let visited = { trail: ['/'], at: 0 };
  assert.equal(View.step(visited, -1), visited);
  assert.equal(View.step(visited, 1), visited);
  assert.equal(View.visit(visited, '/'), visited);

  visited = View.visit(View.visit(visited, '/settings'), '/log');
  assert.deepEqual(visited, { trail: ['/', '/settings', '/log'], at: 2 });
  assert.equal(View.step(visited, 1), visited);

  visited = View.step(View.step(visited, -1), -1);
  assert.deepEqual(visited, { trail: ['/', '/settings', '/log'], at: 0 });
  visited = View.step(visited, 1);
  assert.equal(visited.at, 1);
  // Going somewhere new from the middle forgets the pages that were ahead.
  visited = View.visit(visited, '/');
  assert.deepEqual(visited, { trail: ['/', '/settings', '/'], at: 2 });
});

test('a client waiting for a sign-in shows in the pill', () => {
  const waiting = { waiting: 1, connected: 0, sessions_ending_soon: 0, grants_ending_soon: 0 };
  assert.deepEqual(View.view(running({ attention: waiting })).pill, { text: 'Waiting for you', kind: 'attention' });
  assert.equal(View.view(running({ attention: { ...waiting, waiting: 0 } })).pill.text, 'Running');
});

test('until Windows trusts the certificate no page opens, and Trust is offered', () => {
  const s = running({ window_untrusted: true, can_trust: true });
  // Not even a passkey can be asked for: the broker's page cannot load.
  const view = View.view(s, true);
  assert.equal(view.panel, 'signin');
  assert.equal(view.pages, false);
  assert.deepEqual(view.nav, { home: false, settings: false, log: false });
  assert.equal(view.canSignOut, true);
  const [notice] = View.notices(s, '');
  assert.equal(notice.id, 'trust');
  assert.equal(notice.kind, 'warn');
  assert.equal(notice.action.label, 'Trust certificate');
  assert.equal(notice.action.command, 'trust_certificate');
});

test('hovering over Trust certificate says what it does, and for which sites', () => {
  const [notice] = View.notices(running({ window_untrusted: true, can_trust: true }), '');
  assert.match(notice.action.hint, /trusted roots of your Windows account/);
  assert.match(notice.action.hint, /any certificate that CA signs, for any site/);
  assert.match(notice.action.hint, /Windows asks you to confirm/);
  // It is a hover, not more text on the page.
  assert.doesNotMatch(notice.text, /any site/);
  // The update button needs no such warning.
  const [update] = View.notices(running({ outdated: true, can_update: true }), '');
  assert.equal(update.action.hint, undefined);
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
  assert.deepEqual(View.view(s, true).nav, { home: true, settings: false, log: false });
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
  assert.equal(View.view(s).canSignOut, false);
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
  const body = html.slice(html.indexOf('<body>')).replace(/<!--[\s\S]*?-->/g, '');
  const text = body.replace(/<[^>]+>/g, '\n').split('\n').map((line) => line.trim()).filter(Boolean);
  assert.deepEqual(text, [
    'Synology Broker', '1', 'Windows password', '2', 'Passkey',
    'Start Broker', 'Back', 'Clients', 'Settings', 'Log', 'Sign out',
  ]);
  assert.doesNotMatch(body, /quit|footer|tray|browser/i);
  // The progress bar, the passkey step and the sidebar are hidden until they apply.
  assert.match(html, /<div id="progress-panel" hidden>/);
  assert.match(html, /<div id="signin-panel" hidden>/);
  assert.match(html, /<div id="shell" hidden>/);
  // The password box says what it is for, to anyone who hovers or listens, and shows no text.
  assert.match(html, /<input id="password" type="password"[^>]*aria-label="Windows password for the Synbroker account">/);
  assert.doesNotMatch(html, /placeholder=/);
  // One place for each of the broker's views to sit, and the notices come last.
  assert.ok(html.includes('id="card-slot"') && html.includes('id="page-slot"'));
  assert.ok(body.indexOf('id="notices"') > body.indexOf('id="shell"'));
});

test('the title bar has the menu, Back, Forward and the status dot on the left, and the window buttons on the right', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'ui', 'index.html'), 'utf8');
  const bar = html.slice(html.indexOf('<header id="titlebar"'), html.indexOf('</header>'));
  const order = ['id="menu"', 'id="back"', 'id="forward"', 'id="dot"', 'id="win-min"', 'id="win-max"', 'id="win-close"'];
  const at = order.map((id) => bar.indexOf(id));
  assert.ok(at.every((index) => index > -1), 'a title bar control is missing');
  assert.deepEqual([...at].sort((a, b) => a - b), at, 'the controls are not in order');
  // The bar can be dragged, and is the window's only title: no name on it.
  assert.match(bar, /^<header id="titlebar" data-tauri-drag-region>/);
  assert.doesNotMatch(bar, /Synology Broker/);
  // Until there is a sidebar and pages to go back through, the first three do nothing.
  for (const id of ['menu', 'back', 'forward']) assert.match(bar, new RegExp(`id="${id}"[^>]*disabled`));
});

test('the card carries the logo in both colour schemes, and both files exist', () => {
  const dir = path.join(__dirname, '..', 'ui');
  const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(dir, 'style.css'), 'utf8');
  for (const name of ['logo-light.png', 'logo-dark.png']) {
    assert.ok(html.includes(`src="${name}"`), `${name} is not on the page`);
    assert.ok(fs.statSync(path.join(dir, name)).size > 100, `${name} is missing`);
  }
  assert.match(css, /\.card h1 img\.logo-dark\{display:none\}/);
  assert.match(css, /prefers-color-scheme:dark\)\{\.card h1 img\.logo-light\{display:none\}\.card h1 img\.logo-dark\{display:block\}\}/);
});

test('the window has no frame of its own, and the maximise button is back', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src-tauri', 'src', 'main.rs'), 'utf8');
  assert.match(main, /\.decorations\(false\)/);
  assert.doesNotMatch(main, /\.maximizable\(false\)|\.resizable\(false\)/);
  const capability = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src-tauri', 'capabilities', 'default.json'), 'utf8'));
  for (const name of ['minimize', 'toggle-maximize', 'is-maximized', 'start-dragging', 'close']) {
    assert.ok(capability.permissions.includes(`core:window:allow-${name}`), `core:window:allow-${name} is not granted`);
  }
});

test('only the app\'s own view is granted anything, and nothing is granted to a remote page', () => {
  const dir = path.join(__dirname, '..', 'src-tauri', 'capabilities');
  const files = fs.readdirSync(dir).filter((name) => name.endsWith('.json'));
  assert.deepEqual(files, ['default.json']);
  const capability = JSON.parse(fs.readFileSync(path.join(dir, files[0]), 'utf8'));
  // The broker's page is a second view in the same window. A capability given to the
  // window would be given to it too, so this one names the app's own view.
  assert.deepEqual(capability.webviews, ['main']);
  assert.equal(capability.windows, undefined);
  assert.equal(capability.remote, undefined);
  assert.notEqual(capability.local, false);
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
