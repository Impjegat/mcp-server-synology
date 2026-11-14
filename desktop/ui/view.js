// What the control window shows for a given status. Pure functions, so they can be
// tested without a window (desktop/tests/view.test.js); app.js only applies them.
(function (root) {
  'use strict';

  const PILL = { stopped: 'Stopped', starting: 'Starting', running: 'Running', error: 'Problem' };

  /** `PC\name` becomes `Name`: what the password label calls the account. */
  function accountName(account) {
    const text = String(account || '').trim();
    const name = text.includes('\\') ? text.slice(text.lastIndexOf('\\') + 1) : text;
    if (!name) return 'broker';
    return /^[a-z][a-z0-9_-]*$/.test(name) ? name[0].toUpperCase() + name.slice(1) : name;
  }

  // Where the bar is in each stage of a start: where the stage begins, where it eases
  // to, and how fast (milliseconds). The app cannot know how long the broker takes, so
  // the bar approaches the end of a stage and never claims to have reached it.
  const STAGES = { updating: [4, 45, 7000], launching: [8, 50, 1500], waiting: [50, 96, 9000] };

  /**
   * The bar's value (0 to 99) after `msInStage` in `stage`. `floor` is what it already
   * shows: it never moves back. 100 is only ever set when the broker answers.
   */
  function progress(stage, msInStage, floor) {
    const [from, to, pace] = STAGES[stage] || STAGES.launching;
    const eased = from + (to - from) * (1 - Math.exp(-Math.max(0, msInStage || 0) / pace));
    return Math.min(99, Math.max(floor || 0, Math.round(eased)));
  }

  /** Which panel, pill, labels and buttons a status calls for. */
  function view(status) {
    const s = status || {};
    const running = s.phase === 'running';
    const starting = s.phase === 'starting';
    const waiting = running && Boolean(s.attention) && s.attention.waiting > 0;
    const name = accountName(s.account);
    // A page of the broker can only open here once Windows trusts its certificate.
    const pages = running && !s.window_untrusted;
    return {
      panel: running ? 'running' : starting ? 'progress' : 'start',
      pill: {
        text: waiting ? 'Waiting for you' : starting && s.stage === 'updating' ? 'Updating' : PILL[s.phase] || 'Stopped',
        kind: waiting ? 'attention' : s.phase || 'stopped',
      },
      passwordLabel: `Windows password for the ${name} account`,
      // The check against a changed settings file, one hover away instead of on screen.
      passwordHint: s.start_command && s.account ? `Starts ${s.start_command} as ${s.account}` : '',
      startLabel: s.update_pending ? 'Update and Start Broker' : 'Start Broker',
      canStart: !starting && !running && !s.config_error,
      progressLabel: s.stage === 'updating' ? 'Updating the broker' : 'Starting the broker',
      buttons: {
        open: pages,
        // These pages do not exist on a broker older than this app.
        loginAll: pages && !s.outdated,
        settings: pages && !s.outdated,
        log: pages && !s.outdated,
        stop: running && !s.external,
      },
    };
  }

  /**
   * Every notice a status calls for, newest cause last. `localError` is a refusal from
   * the last thing the person pressed. A notice with an `action` gets a button that
   * calls that app command.
   */
  function notices(status, localError) {
    const s = status || {};
    const list = [];
    const running = s.phase === 'running';
    if (s.config_error) list.push({ id: 'config', kind: 'error', text: s.config_error });
    if (s.message) list.push({ id: 'message', kind: s.phase === 'error' ? 'error' : 'warn', text: s.message });
    if (localError) list.push({ id: 'local', kind: 'error', text: localError });
    if (running && s.cert_untrusted) {
      list.push({
        id: 'cert',
        kind: 'warn',
        text: 'The broker\'s certificate is not trusted. Set "ca_file" in synology-broker-app.json to its CA certificate.',
      });
    } else if (running && s.window_untrusted) {
      list.push({
        id: 'trust',
        kind: 'warn',
        text: 'Windows does not trust the broker\'s certificate yet, so its pages cannot open here.',
        action: s.can_trust ? { label: 'Trust certificate', command: 'trust_certificate' } : null,
      });
    }
    if (running && s.outdated) {
      list.push({
        id: 'outdated',
        kind: 'warn',
        text: 'This broker is an older version. Sign in all, Settings and Log need the update.',
        action: s.can_update ? { label: 'Update Broker', command: 'prepare_update' } : null,
      });
    }
    if (running && s.external) {
      list.push({
        id: 'external',
        kind: 'warn',
        text: 'This broker was started outside the app, so the app cannot stop it.',
      });
    }
    return list.map((notice) => ({ ...notice, key: `${notice.id}\n${notice.text}` }));
  }

  /** The notices still to show: those the person has not dismissed. */
  function visible(list, dismissed) {
    return list.filter((notice) => !dismissed.has(notice.key));
  }

  /**
   * The dismissals worth keeping: only those whose notice is still called for. Once its
   * cause goes away a dismissal is forgotten, so the notice shows again if it returns.
   */
  function reconcile(dismissed, list) {
    const present = new Set(list.map((notice) => notice.key));
    return new Set([...dismissed].filter((key) => present.has(key)));
  }

  const api = { accountName, progress, view, notices, visible, reconcile };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.BrokerView = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
