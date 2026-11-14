// The control window. It never shows or keeps a NAS credential: the only secret it
// touches is the broker's Windows account password, which goes to the app's Rust side
// and is cleared from this page as soon as it is sent. What to show for a status is
// decided in view.js; this file only puts it on the page.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const View = window.BrokerView;

const $ = (id) => document.getElementById(id);
const els = {
  pill: $('pill'),
  startPanel: $('start-panel'), progressPanel: $('progress-panel'), runningPanel: $('running-panel'),
  form: $('start-form'), passwordLabel: $('password-label'), password: $('password'), start: $('start'),
  progress: $('progress'), bar: $('progress-bar'),
  open: $('open'), loginAll: $('login-all'), settings: $('settings'), log: $('log'), stop: $('stop'),
  notices: $('notices'),
};

let status = null;
let localError = '';
let dismissed = new Set();
// The start in progress: which stage the bar is in, since when, and what it shows.
const run = { stage: null, since: 0, shown: 0, timer: null, finishing: false };
const busy = new Set();

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

function showPanel(panel) {
  els.startPanel.hidden = panel !== 'start';
  els.progressPanel.hidden = panel !== 'progress';
  els.runningPanel.hidden = panel !== 'running';
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

function render(next) {
  const before = status ? status.phase : null;
  status = next;
  const view = View.view(status);

  els.pill.textContent = view.pill.text;
  els.pill.className = `pill ${view.pill.kind}`;
  els.passwordLabel.textContent = view.passwordLabel;
  els.passwordLabel.title = view.passwordHint;
  els.start.textContent = view.startLabel;
  els.start.disabled = !view.canStart;
  els.password.disabled = !view.canStart;
  els.progress.setAttribute('aria-label', view.progressLabel);
  els.open.disabled = !view.buttons.open;
  els.loginAll.disabled = !view.buttons.loginAll;
  els.settings.disabled = !view.buttons.settings;
  els.log.disabled = !view.buttons.log;
  els.stop.disabled = !view.buttons.stop;

  if (view.panel === 'progress') {
    if (run.stage !== status.stage) {
      if (run.stage === null) setBar(0);
      run.stage = status.stage;
      run.since = Date.now();
    }
    if (!run.timer) run.timer = setInterval(stepBar, 200);
    stepBar();
    showPanel('progress');
  } else if (view.panel === 'running' && before === 'starting' && !run.finishing) {
    // The broker answered: fill the bar, and only then show what it can do.
    stopBar();
    run.finishing = true;
    setBar(100);
    setTimeout(() => {
      run.finishing = false;
      if (status) showPanel(View.view(status).panel);
    }, 450);
  } else if (!run.finishing) {
    stopBar();
    showPanel(view.panel);
  }
  renderNotices();
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

for (const button of [els.open, els.loginAll, els.settings, els.log]) {
  button.addEventListener('click', () => call('open_broker', { path: button.dataset.page }));
}
els.stop.addEventListener('click', () => call('stop_broker'));

listen('broker-status', (event) => render(event.payload));
invoke('get_status').then(render).catch((error) => { localError = String(error); renderNotices(); });
