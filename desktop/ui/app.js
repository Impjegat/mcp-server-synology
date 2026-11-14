// The control window. It never shows or keeps a NAS credential: the only secret it
// touches is the broker's Windows account password, which goes to the app's Rust side
// and is cleared from this page as soon as it is sent.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const els = {
  pill: $('pill'), message: $('message'), configError: $('config-error'),
  startPanel: $('start-panel'), runningPanel: $('running-panel'),
  command: $('command'), account: $('account'),
  form: $('start-form'), password: $('password'), start: $('start'),
  counts: $('counts'), stop: $('stop'), externalNote: $('external-note'), certNote: $('cert-note'),
};

const LABELS = { stopped: 'Stopped', starting: 'Starting', running: 'Running', error: 'Problem' };

function setMessage(text, isError) {
  els.message.textContent = text || '';
  els.message.hidden = !text;
  els.message.classList.toggle('error', Boolean(isError));
}

function describeCounts(a) {
  if (!a) return '';
  const parts = [`${a.connected} connected`];
  if (a.waiting) parts.push(`${a.waiting} waiting for you`);
  if (a.sessions_ending_soon) parts.push(`${a.sessions_ending_soon} ending soon`);
  if (a.grants_ending_soon) parts.push(`${a.grants_ending_soon} grant(s) to renew`);
  return parts.join(' · ');
}

function render(status) {
  const attention = status.phase === 'running' && status.attention && status.attention.waiting > 0;
  els.pill.textContent = attention ? 'Waiting for you' : LABELS[status.phase] || status.phase;
  els.pill.className = 'pill ' + (attention ? 'attention' : status.phase);

  els.command.textContent = status.start_command;
  els.account.textContent = status.account;
  els.configError.textContent = status.config_error || '';
  els.configError.hidden = !status.config_error;

  const running = status.phase === 'running';
  const starting = status.phase === 'starting';
  els.startPanel.hidden = running;
  els.runningPanel.hidden = !running;
  els.password.disabled = starting || Boolean(status.config_error);
  els.start.disabled = starting || Boolean(status.config_error);
  els.start.textContent = starting ? 'Starting...' : 'Start broker';

  els.counts.textContent = describeCounts(status.attention);
  els.stop.disabled = Boolean(status.external);
  els.externalNote.hidden = !status.external;

  const noneTrust = running && Boolean(status.cert_untrusted);
  const windowOnly = running && !noneTrust && Boolean(status.window_untrusted);
  els.certNote.hidden = !(noneTrust || windowOnly);
  els.certNote.textContent = noneTrust
    ? 'The broker is running, but its certificate is not trusted, so the tray cannot read its alerts and a window ' +
      'here cannot use passkeys. Buttons open your browser instead. To fix it, set "ca_file" in ' +
      'synology-broker-app.json to the CA certificate that signed it (see the README).'
    : windowOnly
      ? 'Windows does not trust the broker\'s certificate (only the ca_file does), so a window here cannot use ' +
        'passkeys. The buttons open your browser instead. See the README to trust the CA for a window.'
      : '';

  setMessage(status.message, status.phase === 'error');
}

els.form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = els.password.value;
  els.password.value = '';
  if (!password) { setMessage('Enter the password for the broker\'s Windows account.', true); return; }
  try {
    await invoke('start_broker', { password });
  } catch (error) {
    setMessage(String(error), true);
  }
});

const open = (path) => () => invoke('open_broker', { path }).catch((e) => setMessage(String(e), true));
$('open').addEventListener('click', open('/'));
$('open-browser').addEventListener('click', () => invoke('open_browser', { path: '/' }).catch((e) => setMessage(String(e), true)));
$('login-all').addEventListener('click', open('/login-all'));
$('log').addEventListener('click', open('/log'));
$('stop').addEventListener('click', () => invoke('stop_broker').catch((e) => setMessage(String(e), true)));
$('quit').addEventListener('click', () => invoke('quit_app'));

listen('broker-status', (event) => render(event.payload));
invoke('get_status').then(render).catch((e) => setMessage(String(e), true));
