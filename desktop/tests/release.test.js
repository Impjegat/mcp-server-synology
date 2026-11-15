// The app's two development switches let a debug build run commands as the developer's
// own account and assume a certificate is trusted. They must never reach a release
// build. A release binary was checked by hand; this keeps it true by reading the
// source, which needs no Rust toolchain and so can run in CI on every change.
// Run with: node --test desktop/tests/release.test.js
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src-tauri', 'src');
const SWITCH = /SYNOLOGY_BROKER_DEV_[A-Z_]+/;
const DEBUG_ONLY = '#[cfg(debug_assertions)]';
const RELEASE_ONLY = '#[cfg(not(debug_assertions))]';

const sources = () => fs.readdirSync(SRC)
  .filter((name) => name.endsWith('.rs'))
  .map((name) => ({ name, lines: fs.readFileSync(path.join(SRC, name), 'utf8').split(/\r?\n/) }));

const isComment = (line) => /^\s*\/\//.test(line);

/** The first line of the item (a function, constant or binding) that line `index` is in. */
function itemStart(lines, index) {
  let at = index;
  while (at > 0 && !/^\s*(pub(\([a-z]+\))?\s+)?(async\s+)?(fn|const|static|let)\b/.test(lines[at])) at -= 1;
  return at;
}

/** The attributes written directly above line `index`, comments between them skipped. */
function attributesAbove(lines, index) {
  const found = [];
  for (let at = index - 1; at >= 0; at -= 1) {
    const line = lines[at].trim();
    if (line.startsWith('#[')) found.push(line);
    else if (!isComment(line)) break;
  }
  return found;
}

/** Every place a switch is named in code (not in a comment). */
function uses() {
  const found = [];
  for (const { name, lines } of sources()) {
    lines.forEach((line, index) => {
      const match = line.match(SWITCH);
      if (match && !isComment(line)) found.push({ name, lines, index, variable: match[0] });
    });
  }
  return found;
}

test('each development switch is named only inside an item compiled for debug builds', () => {
  const found = uses();
  for (const { name, lines, index, variable } of found) {
    const start = itemStart(lines, index);
    assert.ok(
      attributesAbove(lines, start).includes(DEBUG_ONLY),
      `${name}:${index + 1} names ${variable} in an item that is not marked ${DEBUG_ONLY}`,
    );
  }
  // Both switches exist, each named once: this test would pass on nothing otherwise.
  assert.deepEqual(
    found.map((use) => use.variable).sort(),
    ['SYNOLOGY_BROKER_DEV_ASSUME_TRUSTED', 'SYNOLOGY_BROKER_DEV_RUN_AS_SELF'],
  );
});

test('a release build is told that Windows trust is never assumed', () => {
  const { lines } = sources().find((source) => source.name === 'monitor.rs');
  const at = lines.findIndex((line, index) =>
    /fn dev_assume_windows_trusts\(\)/.test(line) && attributesAbove(lines, index).includes(RELEASE_ONLY));
  assert.notEqual(at, -1, 'the release-build version of dev_assume_windows_trusts is missing');
  const body = [];
  for (let index = at + 1; lines[index].trim() !== '}'; index += 1) body.push(lines[index].trim());
  assert.deepEqual(body, ['false']);
});

test('a release build signs in to Windows, with no other way to start a process', () => {
  const { lines } = sources().find((source) => source.name === 'launch.rs');
  // The call that starts a process without a sign-in appears once, in a debug-only binding.
  const unsigned = lines
    .map((line, index) => ({ line, index }))
    .filter(({ line }) => /\bCreateProcessW\(/.test(line) && !isComment(line));
  assert.equal(unsigned.length, 1);
  assert.ok(attributesAbove(lines, itemStart(lines, unsigned[0].index)).includes(DEBUG_ONLY));
  // And the release-only binding is the signed-in one, alone.
  const release = lines.findIndex((line, index) =>
    /^\s*let result = /.test(line) && attributesAbove(lines, index).includes(RELEASE_ONLY));
  assert.notEqual(release, -1, 'the release-build way to start a process is missing');
  assert.match(lines[release], /let result = signed_in\(&mut command, &mut info\);/);
});

// The broker says how new its private page is (PRIVATE_PAGE_LEVEL) and the app says how
// new it needs it to be (REQUIRED_LEVEL). They are two numbers in two languages, kept in
// step by hand: raising the app's without the broker's would make the app call every
// broker "older", this repository's own included, and offer an update that cannot help.
test('the app does not need a newer broker than this repository has', () => {
  const number = (file, pattern) => {
    const match = fs.readFileSync(path.join(ROOT, file), 'utf8').match(pattern);
    assert.ok(match, `${pattern} was not found in ${file}`);
    return Number(match[1]);
  };
  const required = number('src-tauri/src/state.rs', /^pub const REQUIRED_LEVEL: u32 = (\d+);$/m);
  const provided = number('../src/private_auth/app.py', /^PRIVATE_PAGE_LEVEL = (\d+)\r?$/m);
  assert.ok(required >= 1 && provided >= 1);
  assert.ok(
    required <= provided,
    `the app needs level ${required}, but the broker in this repository reports ${provided}`,
  );
});

test('every page the app opens or reads is one the broker in this repository serves', () => {
  const read = (file) => fs.readFileSync(path.join(ROOT, file), 'utf8');
  const pages = read('src-tauri/src/commands.rs').match(/^const PAGES: \[&str; \d+\] = \[([^\]]+)\];$/m);
  assert.ok(pages, 'the list of pages the app opens was not found in commands.rs');
  const opened = [...pages[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(opened, ['/', '/log', '/settings']);

  // The two endpoints the monitor reads, each of which it must really ask for.
  const monitor = read('src-tauri/src/monitor.rs');
  const readByMonitor = ['/healthz', '/attention'];
  for (const endpoint of readByMonitor) {
    assert.match(monitor, new RegExp(`format!\\("\\{[a-z]*\\}${endpoint}"`), `${endpoint} is not read by monitor.rs`);
  }

  const broker = read('../src/private_auth/app.py');
  for (const page of [...opened, ...readByMonitor]) {
    const route = `Route("${page}", self.`;
    const line = broker.split(/\r?\n/).find((text) => text.includes(route) && text.includes('methods=["GET"]'));
    assert.ok(line, `the broker has no GET route for ${page}`);
  }
});

// The broker reads the app's name in the user agent of the view that shows its page, and
// then leaves out the navigation the app has already got. Two spellings, two languages.
test('the app calls its page by the name the broker looks for', () => {
  const read = (file) => fs.readFileSync(path.join(ROOT, file), 'utf8');
  const agent = read('src-tauri/src/commands.rs').match(/const PAGE_USER_AGENT: &str = "[^"]*\b(SynologyBrokerApp\/)\d+"/);
  assert.ok(agent, 'the app\'s user agent was not found in commands.rs');
  const broker = read('../src/private_auth/app.py').match(/^APP_USER_AGENT = "([^"]+)"$/m);
  assert.ok(broker, 'the broker\'s APP_USER_AGENT was not found');
  assert.equal(broker[1], agent[1]);
});

test('the guide says both switches exist only in debug builds', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  for (const { variable } of uses()) assert.ok(readme.includes(variable), `${variable} is not documented`);
  assert.match(readme, /A \*\*debug\*\* build[^\n]*has two switches that a release build does not contain/);
});
