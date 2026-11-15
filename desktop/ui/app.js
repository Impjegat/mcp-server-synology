// The app's one window. Before the passkey is accepted it shows a card with two steps
// (Windows password, then passkey); afterwards a sidebar and the broker's pages.
//
// The broker's pages are not drawn here. They are a remote page, shown in a view of
// their own that this window places over `#card-slot` or `#page-slot`: that view has no
// capability and cannot call anything in the app. What this window learns about it is
// two sentences from the app (its title, and the path it moved to), and all that it does
// with them is decide what to show. It never sees the NAS password, the one-time code or
// a session, and the only secret it touches is the broker's Windows account password,
// which goes to the app's Rust side and is cleared from this page as soon as it is sent.
// What to show for a status is decided in view.js; this file only puts it on the page.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const appWindow = window.__TAURI__.window.getCurrentWindow();
const View = window.BrokerView;

const $ = (id) => document.getElementById(id);
const els = {
  gate: $('gate'), shell: $('shell'), dock: $('dock'),
  dot: $('dot'), menu: $('menu'), back: $('back'), forward: $('forward'), maxButton: $('win-max'), maxIcon: $('max-icon'),
  step1: $('step1'), step2: $('step2'), line: $('line'),
  form: $('start-form'), password: $('password'), start: $('start'),
  progressPanel: $('progress-panel'), progress: $('progress'), bar: $('progress-bar'),
  signinPanel: $('signin-panel'), cardSlot: $('card-slot'), gateBack: $('gate-back'),
  pageSlot: $('page-slot'),
  nav: document.querySelectorAll('#nav a'), badge: $('badge'), signout: $('signout'),
  notices: $('notices'),
};

let status = null;
let lastView = null;
let localError = '';
let dismissed = new Set();
// The title of the broker's page, which says whether the passkey has been given.
let pageTitle = null;
// The pages visited, for Back and Forward, and the page this window itself just asked for
// (so that the broker's page arriving there is not taken for a visit of its own).
let visited = { trail: ['/'], at: 0 };
let pendingNav = null;
// The start in progress: which stage the bar is in, since when, and what it shows.
const run = { stage: null, since: 0, shown: 0, timer: null, finishing: false };
const busy = new Set();
let pageShown = false;
let placing = 0;

function setBar(value) {
  run.shown = value;
  els.bar.style.width = `${value}%`;
  els.progress.setAttribute('aria-valuenow', String(value));
}

function stepBar() {
  setBar(View.progress(run.stage, Date.now() - run.since, run.shown));
}

function stopBar() {
  clearInterval(run.timer);
  run.timer = null;
  run.stage = null;
}

/** Which of the two steps the card is on: the password (start, progress) or the passkey. */
function setSteps(second) {
  els.step1.className = `step ${second ? 'done' : 'active'}`;
  els.step2.className = `step ${second ? 'active' : ''}`;
  els.step1.firstElementChild.textContent = second ? '✓' : '1';
  els.line.className = `line${second ? ' done' : ''}`;
  if (second) {
    els.step2.setAttribute('aria-current', 'step');
    els.step1.removeAttribute('aria-current');
  } else {
    els.step1.setAttribute('aria-current', 'step');
    els.step2.removeAttribute('aria-current');
  }
}

function showPanel(panel) {
  const inShell = panel === 'shell';
  els.gate.hidden = inShell;
  els.shell.hidden = !inShell;
  els.form.hidden = panel !== 'start';
  els.progressPanel.hidden = panel !== 'progress';
  els.signinPanel.hidden = panel !== 'signin';
  // In the sidebar layout the notices sit under the page, so the page's view stops above them.
  (inShell ? els.dock : document.body).append(els.notices);
  if (!inShell) setSteps(panel === 'signin');
}

function renderNotices() {
  const all = View.notices(status, localError);
  dismissed = View.reconcile(dismissed, all);
  els.notices.replaceChildren(...View.visible(all, dismissed).map((notice) => {
    const card = document.createElement('div');
    card.className = `notice ${notice.kind}`;
    card.dataset.id = notice.id;
    const text = document.createElement('p');
    text.textContent = notice.text;
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'close';
    close.textContent = '×';
    close.setAttribute('aria-label', 'Dismiss');
    close.addEventListener('click', () => {
      if (notice.id === 'local') localError = '';
      else dismissed.add(notice.key);
      renderNotices();
    });
    card.append(text, close);
    if (notice.action) {
      const act = document.createElement('button');
      act.type = 'button';
      act.className = 'action';
      act.textContent = notice.action.label;
      act.title = notice.action.hint || '';
      act.disabled = busy.has(notice.action.command);
      act.addEventListener('click', () => call(notice.action.command));
      card.append(act);
    }
    return card;
  }));
}

// -- the broker's page ------------------------------------------------------------

/** Put the broker's page where the slot for the panel on show is, or take it away. */
function placePage() {
  cancelAnimationFrame(placing);
  placing = requestAnimationFrame(async () => {
    const view = lastView;
    const slot = view && view.pages && !run.finishing
      ? { shell: els.pageSlot, signin: els.cardSlot }[view.panel]
      : null;
    if (!slot) {
      if (pageShown) {
        pageShown = false;
        invoke('hide_page').catch(() => {});
      }
      return;
    }
    const box = slot.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) return;
    pageShown = true;
    try {
      await invoke('place_page', {
        bounds: { x: box.left, y: box.top, width: box.width, height: box.height },
        path: visited.trail[visited.at],
      });
    } catch (error) {
      pageShown = false;
      localError = String(error);
      renderNotices();
    }
  });
}

/** Ask the broker's page for another page of the broker's. */
function openPage(path) {
  pendingNav = path;
  invoke('open_broker', { path }).catch((error) => {
    pendingNav = null;
    localError = String(error);
    renderNotices();
  });
}

function go(path) {
  visited = View.visit(visited, path);
  openPage(path);
  render();
}

function stepHistory(by) {
  const next = View.step(visited, by);
  if (next === visited) return;
  visited = next;
  openPage(visited.trail[visited.at]);
  render();
}

function resetPage() {
  pageTitle = null;
  pendingNav = null;
  visited = { trail: ['/'], at: 0 };
}

// -- drawing ------------------------------------------------------------------------

function render(next) {
  const before = status ? status.phase : null;
  if (next) {
    status = next;
    if (status.phase !== 'running') resetPage();
  }
  if (!status) return;
  const view = View.view(status, View.signedIn(pageTitle));
  lastView = view;

  els.dot.className = `dot ${view.pill.kind}`;
  els.dot.title = view.pill.text;
  els.dot.setAttribute('aria-label', view.pill.text);
  els.password.setAttribute('aria-label', view.passwordLabel);
  els.password.title = view.passwordHint;
  els.start.textContent = view.startLabel;
  els.start.disabled = !view.canStart;
  els.password.disabled = !view.canStart;
  els.progress.setAttribute('aria-label', view.progressLabel);
  els.gateBack.disabled = !view.canSignOut;
  els.signout.disabled = !view.canSignOut;
  els.nav.forEach((link) => {
    link.setAttribute('aria-disabled', String(!view.nav[link.dataset.nav]));
    link.classList.toggle('current', View.section(visited.trail[visited.at]) === link.getAttribute('href'));
  });
  els.badge.hidden = !view.waiting;
  els.badge.textContent = String(view.waiting);
  const inShell = view.panel === 'shell';
  els.menu.disabled = !inShell;
  els.back.disabled = !inShell || visited.at === 0;
  els.forward.disabled = !inShell || visited.at === visited.trail.length - 1;

  if (view.panel === 'progress') {
    if (run.stage !== status.stage) {
      if (run.stage === null) setBar(0);
      run.stage = status.stage;
      run.since = Date.now();
    }
    if (!run.timer) run.timer = setInterval(stepBar, 200);
    stepBar();
    showPanel('progress');
  } else if (status.phase === 'running' && before === 'starting' && !run.finishing) {
    // The broker answered: fill the bar, then go on to the passkey.
    stopBar();
    run.finishing = true;
    setBar(100);
    setTimeout(() => {
      run.finishing = false;
      if (status) render();
    }, 450);
  } else if (!run.finishing) {
    stopBar();
    showPanel(view.panel);
  }
  renderNotices();
  placePage();
}

async function call(command, args) {
  localError = '';
  busy.add(command);
  renderNotices();
  try {
    await invoke(command, args);
  } catch (error) {
    localError = String(error);
  } finally {
    busy.delete(command);
    renderNotices();
  }
}

async function syncMaximised() {
  const maximised = await appWindow.isMaximized().catch(() => false);
  els.maxButton.title = maximised ? 'Restore' : 'Maximise';
  els.maxButton.setAttribute('aria-label', els.maxButton.title);
  els.maxIcon.innerHTML = maximised
    ? '<path d="M2.5 2.5V.5h7v7h-2M.5 2.5h7v7h-7z" fill="none" stroke="currentColor" stroke-width="1"/>'
    : '<rect x=".5" y=".5" width="9" height="9" fill="none" stroke="currentColor" stroke-width="1"/>';
}

els.form.addEventListener('submit', (event) => {
  event.preventDefault();
  const password = els.password.value;
  els.password.value = '';
  if (!password) {
    localError = 'Enter the password for the broker\'s Windows account.';
    renderNotices();
    return;
  }
  call('start_broker', { password });
});

// One way out: stop the broker and go back to the Windows password.
els.gateBack.addEventListener('click', () => call('stop_broker'));
els.signout.addEventListener('click', () => call('stop_broker'));

els.nav.forEach((link) => link.addEventListener('click', (event) => {
  event.preventDefault();
  if (link.getAttribute('aria-disabled') !== 'true') go(link.getAttribute('href'));
}));
els.menu.addEventListener('click', () => {
  const hidden = document.body.classList.toggle('collapsed');
  els.menu.title = hidden ? 'Show sidebar' : 'Hide sidebar';
  els.menu.setAttribute('aria-label', els.menu.title);
});
els.back.addEventListener('click', () => stepHistory(-1));
els.forward.addEventListener('click', () => stepHistory(1));
$('win-min').addEventListener('click', () => appWindow.minimize());
els.maxButton.addEventListener('click', () => appWindow.toggleMaximize());
// Closing asks the app, which asks whether to stop the broker if this app started one.
$('win-close').addEventListener('click', () => appWindow.close());

// Wherever the slot goes (the sidebar is hidden, the window is resized, a notice comes
// or goes), the broker's page follows it.
const watcher = new ResizeObserver(() => placePage());
watcher.observe(els.cardSlot);
watcher.observe(els.pageSlot);

listen('broker-status', (event) => render(event.payload));
listen('page-title', (event) => {
  // A page that arrives after the broker stopped is the blank one it is left on.
  if (!status || status.phase !== 'running') return;
  pageTitle = String(event.payload);
  render();
});
listen('page-route', (event) => {
  const path = View.section(String(event.payload));
  if (pendingNav !== null && View.section(pendingNav) === path) pendingNav = null;
  else visited = View.visit(visited, path);
  render();
});
// The tray's menu asks for a page.
listen('open-page', (event) => {
  if (lastView && lastView.panel === 'shell') go(View.section(String(event.payload)));
});
appWindow.onResized(syncMaximised);
syncMaximised();
invoke('get_status').then(render).catch((error) => { localError = String(error); renderNotices(); });
