// What the app's window shows for a given status. Pure functions, so they can be
// tested without a window (desktop/tests/view.test.js); app.js only applies them.
(function (root) {
  'use strict';

  const PILL = { stopped: 'Stopped', starting: 'Starting', running: 'Running', error: 'Problem' };

  /** `PC\name` becomes `Name`: what the password box calls the account. */
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

  // The broker's page names itself in its title, and the app reads that to tell whether
  // the passkey has been given: these are the pages shown before it. (The first is what
  // the page is called now; the second is what a broker older than this app calls it.)
  const SIGNED_OUT = ['Sign in', 'Private sign-in', 'No owner enrolled', 'Enroll a passkey'];

  /** Whether the page titled `title` is one only a signed-in owner sees. No title yet is not. */
  function signedIn(title) {
    return typeof title === 'string' && title !== '' && title !== 'about:blank' && !SIGNED_OUT.includes(title);
  }

  /** Which sidebar entry a path of the broker's belongs to. */
  function section(path) {
    return path === '/settings' || path === '/log' ? path : '/';
  }

  /** The pages visited, for Back and Forward. Visiting the page already shown changes nothing. */
  function visit(history, path) {
    if (history.trail[history.at] === path) return history;
    const trail = history.trail.slice(0, history.at + 1).concat(path);
    return { trail, at: trail.length - 1 };
  }

  /** One step back (`-1`) or forward (`1`); no step at either end. */
  function step(history, by) {
    const at = history.at + by;
    return at < 0 || at >= history.trail.length ? history : { trail: history.trail, at };
  }

  /**
   * What the one window shows for a status. `isSignedIn` is whether the broker's page
   * says the passkey has been accepted: until then the window is the card in the middle
   * (start, progress, then the passkey, which the broker's own page asks for); afterwards
   * it is the sidebar and the broker's pages.
   */
  function view(status, isSignedIn) {
    const s = status || {};
    const running = s.phase === 'running';
    const starting = s.phase === 'starting';
    const count = running && s.attention ? s.attention.waiting || 0 : 0;
    const name = accountName(s.account);
    // The broker's pages can only open here once Windows trusts its certificate.
    const pages = running && !s.window_untrusted;
    return {
      panel: running ? (isSignedIn && pages ? 'shell' : 'signin') : starting ? 'progress' : 'start',
      pill: {
        text: count ? 'Waiting for you' : starting && s.stage === 'updating' ? 'Updating' : PILL[s.phase] || 'Stopped',
        kind: count ? 'attention' : s.phase || 'stopped',
      },
      waiting: count,
      passwordLabel: `Windows password for the ${name} account`,
      // The check against a changed settings file, one hover away instead of on screen.
      passwordHint: s.start_command && s.account ? `Starts ${s.start_command} as ${s.account}` : '',
      startLabel: s.update_pending ? 'Update and Start Broker' : 'Start Broker',
      canStart: !starting && !running && !s.config_error,
      progressLabel: s.stage === 'updating' ? 'Updating the broker' : 'Starting the broker',
      // The broker's page can be shown at all (and so asks for the passkey).
      pages,
      // Sign out stops the broker, which the app can only do to one it started.
      canSignOut: running && !s.external,
      // These pages do not exist on a broker older than this app.
      nav: { home: pages, settings: pages && !s.outdated, log: pages && !s.outdated },
    };
  }

  // What pressing Trust certificate does, for whoever hovers over it. Windows says the
  // same in its own dialog before anything is added; this is so the button is not a
  // surprise.
  const TRUST_HINT = 'Adds the broker\'s CA certificate to the trusted roots of your Windows account. ' +
    'Windows will then trust any certificate that CA signs, for any site. Windows asks you to confirm first.';

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
        text: 'Windows does not trust the broker\'s certificate yet.',
        action: s.can_trust ? { label: 'Trust certificate', command: 'trust_certificate', hint: TRUST_HINT } : null,
      });
    }
    if (running && s.outdated) {
      list.push({
        id: 'outdated',
        kind: 'warn',
        text: 'This broker is an older version. Settings and Log need the update.',
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

  const api = { accountName, progress, signedIn, section, visit, step, view, notices, visible, reconcile };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.BrokerView = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
