import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

// Most of this file is file-text assertions: pkgbuild, productbuild, productsign
// and launchctl exist on macOS only, so the package's behaviour is pinned by
// what the shipped scripts say. The exception is postinstall, which the last
// tests run under sh with every macOS-only command stubbed. Nothing else in this
// file spawns a process.

const read = (name) => readFileSync(fileURLToPath(new URL(`../macos/${name}`, import.meta.url)), 'utf8');

const postinstall = read('scripts/postinstall');
const preinstall = read('scripts/preinstall');
const uninstall = read('uninstall.sh');
const buildSh = read('build.sh');
const distribution = read('distribution.xml');

const CONFIG_PATH = '/Library/Application Support/OfficeHQ/MDM/config.json';
const PLIST_PATH = '/Library/LaunchDaemons/au.com.officehq.mdmagent.plist';
const HEREDOC_OPEN = `cat > "${CONFIG_PATH}" <<EOF`;

/** The script's lines, with the line ending the file happens to use removed. */
const lines = (text) => text.split(/\r?\n/);

/** The last line of the script that is not blank. */
function lastNonEmptyLine(text) {
  const kept = lines(text).filter((line) => line.trim() !== '');
  return kept[kept.length - 1];
}

/**
 * A minimal XML parser: enough to prove distribution.xml is well formed and to
 * read elements and attributes out of it. The project has no XML dependency and
 * Node has no XML parser, and pulling one in for one 18-line file is not worth
 * the supply chain.
 */
function parseXml(source) {
  const token = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<!DOCTYPE[^>]*>|<\/\s*([\w:.-]+)\s*>|<\s*([\w:.-]+)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/g;
  const document = { name: '#document', attributes: {}, children: [], text: '' };
  const stack = [document];
  let cursor = 0;
  let match;

  while ((match = token.exec(source)) !== null) {
    stack[stack.length - 1].text += source.slice(cursor, match.index);
    cursor = token.lastIndex;

    const [, closed, opened, attributes, selfClosing] = match;
    if (closed !== undefined) {
      const open = stack.pop();
      if (stack.length === 0 || open.name !== closed) {
        throw new Error(`unbalanced </${closed}>`);
      }
    } else if (opened !== undefined) {
      const element = { name: opened, attributes: parseAttributes(attributes), children: [], text: '' };
      stack[stack.length - 1].children.push(element);
      if (selfClosing !== '/') {
        stack.push(element);
      }
    }
  }

  if (stack.length !== 1) {
    throw new Error(`unclosed <${stack[stack.length - 1].name}>`);
  }
  return document;
}

function parseAttributes(source) {
  const attributes = {};
  const pattern = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = pattern.exec(source ?? '')) !== null) {
    attributes[match[1]] = match[2] ?? match[3];
  }
  return attributes;
}

/** Every element in the tree with this name, document order. */
function elements(node, name) {
  const found = node.name === name ? [node] : [];
  for (const child of node.children) {
    found.push(...elements(child, name));
  }
  return found;
}

test('postinstall begins with the shebang and set -e', () => {
  const [first, second] = lines(postinstall);
  strictEqual(first, '#!/bin/sh');
  strictEqual(second, 'set -e');
});

test('postinstall secures the config before loading the daemon', () => {
  const chmod = postinstall.indexOf(`chmod 600 "${CONFIG_PATH}"`);
  const chown = postinstall.indexOf(`chown root:wheel "${CONFIG_PATH}"`);
  const bootstrap = postinstall.indexOf(`launchctl bootstrap system ${PLIST_PATH}`);
  ok(chmod !== -1, 'postinstall chmod 600 of the config');
  ok(chown !== -1, 'postinstall chown root:wheel of the config');
  ok(bootstrap !== -1, 'postinstall launchctl bootstrap');
  ok(chmod < bootstrap, 'the config is chmod-ed before the daemon loads');
  ok(chown < bootstrap, 'the config is chown-ed before the daemon loads');
});

test('postinstall writes the config key set the agent loads', () => {
  const text = lines(postinstall);
  const start = text.indexOf(HEREDOC_OPEN);
  ok(start !== -1, 'postinstall opens the config heredoc');
  const end = text.indexOf('EOF', start + 1);
  ok(end !== -1, 'the config heredoc is closed');

  const body = text
    .slice(start + 1, end)
    .join('\n')
    .replaceAll('$COLLECTION_URL', 'https://x.example/')
    .replaceAll('$OWNERSHIP', 'byoc')
    .replaceAll('$TENANT_ID', 'tenant-1')
    .replaceAll('$CLIENT_ID', 'client-1');

  const config = JSON.parse(body);
  deepStrictEqual(config, {
    collectionUrl: 'https://x.example/',
    ownership: 'byoc',
    tenantId: 'tenant-1',
    clientId: 'client-1',
    checkInIntervalSeconds: 900,
    logLevel: 'info',
  });
  ok(!postinstall.includes('enrollmentToken'), 'the new installer never writes an enrollment token');
});

test('postinstall carries the three baked placeholders and defaults to an OfficeHQ device', () => {
  ok(postinstall.includes('BAKED_COLLECTION_URL="__COLLECTION_URL__"'));
  ok(postinstall.includes('TENANT_ID="__TENANT_ID__"'));
  ok(postinstall.includes('CLIENT_ID="__CLIENT_ID__"'));
  ok(postinstall.includes('OWNERSHIP="officehq"'));
  ok(!postinstall.includes('__ENROLL_TOKEN__'));
});

test('postinstall finds the console user and treats root and loginwindow as nobody', () => {
  ok(postinstall.includes('stat -f%Su /dev/console'));
  ok(/""\|root\|loginwindow\) CONSOLE_USER="" ;;/.test(postinstall));
});

test('postinstall asks the console user through launchctl asuser and osascript', () => {
  ok(postinstall.includes('launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" "$@"'));
  ok(postinstall.includes('display dialog'));
  ok(postinstall.includes('choose from list'));
  ok(postinstall.includes('OFFICEHQ_DEVICE="OfficeHQ device"'));
  ok(postinstall.includes('BYOC_DEVICE="BYOC (personal device)"'));
});

const OPEN_SIGNIN =
  'launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" /usr/local/bin/mdmagent open-signin >/dev/null 2>&1 &';

test('postinstall runs mdmagent open-signin as the user, in the background, after the daemon is bootstrapped', () => {
  const bootstrap = postinstall.indexOf(`launchctl bootstrap system ${PLIST_PATH}`);
  const open = postinstall.indexOf(OPEN_SIGNIN);
  ok(open !== -1, 'postinstall runs open-signin as the console user, detached');
  ok(bootstrap < open, 'the sign-in opens after the daemon is loaded');
});

test('postinstall no longer waits for a loopback port or opens a URL itself', () => {
  ok(!/\bnc\b/.test(postinstall), 'no port wait');
  ok(!postinstall.includes('SIGNIN_URL'));
});

test('preinstall tolerates a daemon that is not loaded', () => {
  strictEqual(lines(preinstall)[0], '#!/bin/sh');
  ok(preinstall.includes(`launchctl bootout system ${PLIST_PATH} || true`));
  strictEqual(lastNonEmptyLine(preinstall), 'exit 0');
});

test('uninstall boots the daemon out before deleting anything', () => {
  strictEqual(lines(uninstall)[0], '#!/bin/sh');
  const bootout = uninstall.indexOf(`launchctl bootout system ${PLIST_PATH} || true`);
  ok(bootout !== -1, 'uninstall boots the daemon out');
  for (const removal of [
    'rm -f /usr/local/bin/mdmagent',
    `rm -f ${PLIST_PATH}`,
    'rm -rf "/Library/Application Support/OfficeHQ/MDM"',
  ]) {
    const index = uninstall.indexOf(removal);
    ok(index !== -1, `uninstall runs ${removal}`);
    ok(bootout < index, `the bootout comes before ${removal}`);
  }
  strictEqual(lastNonEmptyLine(uninstall), 'exit 0');
});

test('build.sh signs the package with the configured identity', () => {
  ok(buildSh.includes('productsign --sign "$MDM_SIGN_IDENTITY"'));
});

test('build.sh takes its paths from the planner', () => {
  const invocation = buildSh.indexOf('node "$(dirname "$0")/build-plan.mjs"');
  ok(invocation !== -1, 'build.sh runs build-plan.mjs');
  const line = buildSh.slice(invocation).split(/\r?\n/)[0];
  for (const flag of ['--version', '--arch', '--collection-url', '--tenant-id', '--client-id']) {
    ok(line.includes(flag), `build.sh forwards ${flag}`);
  }
  ok(!buildSh.includes('--enroll-token'), 'build.sh no longer takes an enrollment token');
});

test('build.sh substitutes the three config placeholders', () => {
  const sed = lines(buildSh).find((line) => line.startsWith('sed '));
  ok(sed !== undefined, 'build.sh runs sed over the postinstall script');
  for (const placeholder of ['__COLLECTION_URL__', '__TENANT_ID__', '__CLIENT_ID__']) {
    ok(sed.includes(placeholder), `sed substitutes ${placeholder}`);
  }
});

test('build.sh stages the branded resources and the sign-in command', () => {
  ok(buildSh.includes('--resources "$ROOT/build/resources"'), 'productbuild gets the resources');
  ok(buildSh.includes('branding/macos-background.png'));
  ok(buildSh.includes('branding/logo.png'));
  ok(buildSh.includes('resources/welcome.html'));
  ok(buildSh.includes('"$ROOT/build/root/Applications/OfficeHQ/Sign in to OfficeHQ MDM.command"'));
  ok(buildSh.includes('chmod 755 "$ROOT/build/root/Applications/OfficeHQ/Sign in to OfficeHQ MDM.command"'));
  ok(!buildSh.includes('webloc'));
});

test('distribution.xml shows the branded background and welcome page', () => {
  const [root] = parseXml(distribution).children;
  const [background] = elements(root, 'background');
  strictEqual(background.attributes.file, 'background.png');
  strictEqual(background.attributes.alignment, 'left');
  strictEqual(background.attributes.scaling, 'proportional');
  const [welcome] = elements(root, 'welcome');
  strictEqual(welcome.attributes.file, 'welcome.html');
  strictEqual(welcome.attributes['mime-type'], 'text/html');

  const html = read('resources/welcome.html');
  ok(html.includes('<img src="logo.png"'), 'the welcome page shows the logo');
});

test('the sign-in command runs mdmagent open-signin', () => {
  const command = read('Sign in to OfficeHQ MDM.command');
  strictEqual(lines(command)[0], '#!/bin/sh');
  strictEqual(lastNonEmptyLine(command), 'exec /usr/local/bin/mdmagent open-signin');
  ok(!command.includes('\r'), 'LF line endings, or sh cannot run it');
  ok(
    !existsSync(fileURLToPath(new URL('../macos/Sign in to OfficeHQ MDM.webloc', import.meta.url))),
    'the webloc is gone',
  );
});

test('uninstall removes the sign-in command', () => {
  ok(uninstall.includes('rm -f "/Applications/OfficeHQ/Sign in to OfficeHQ MDM.command"'));
  ok(!uninstall.includes('webloc'));
  ok(uninstall.includes('rmdir /Applications/OfficeHQ 2>/dev/null || true'));
});

test('distribution.xml names the package and the minimum macOS', () => {
  const document = parseXml(distribution);
  const [root] = document.children;
  strictEqual(root.name, 'installer-gui-script');

  const identifiers = elements(root, 'pkg-ref').map((element) => element.attributes.id);
  ok(identifiers.includes('au.com.officehq.mdm.agent'), 'the package identifier is set');

  const [osVersion] = elements(root, 'os-version');
  ok(osVersion !== undefined, 'distribution.xml constrains the host OS version');
  strictEqual(osVersion.attributes.min, '12.0');
});

// ---------------------------------------------------------------------------
// postinstall, run for real under sh with every macOS-only command stubbed and
// every absolute path moved under a temporary root. Skipped where no POSIX sh
// is available.
// ---------------------------------------------------------------------------

const HAS_SH = spawnSync('sh', ['-c', 'exit 0']).status === 0;

const STUBS = {
  stat: 'printf "%s\n" "$STUB_CONSOLE_USER"',
  id: 'echo 501',
  launchctl: [
    'if [ "$1" = asuser ]; then shift 2; exec "$@"; fi',
    'echo "launchctl $*" >> "$STUB_DIR/calls.log"',
  ].join('\n'),
  sudo: 'if [ "$1" = -u ]; then shift 2; fi\nexec "$@"',
  osascript: [
    'n=$(cat "$STUB_DIR/count" 2>/dev/null || echo 0)',
    'n=$((n + 1))',
    'echo "$n" > "$STUB_DIR/count"',
    'for last; do :; done',
    'echo "osascript $last" >> "$STUB_DIR/calls.log"',
    '[ -f "$STUB_DIR/answer.$n" ] && cat "$STUB_DIR/answer.$n"',
    'exit "$(cat "$STUB_DIR/status.$n" 2>/dev/null || echo 1)"',
  ].join('\n'),
  open: 'echo "open $*" >> "$STUB_DIR/calls.log"',
  chown: 'exit 0',
  chmod: 'exit 0',
};

/**
 * Runs postinstall with a console user (or none) and scripted osascript
 * answers ({ status, out } per call, in order). Returns the config written and
 * the stubbed calls.
 */
function runPostinstall({ consoleUser, answers = [], env = {} }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'mdm-postinstall-'));
  try {
    const stubDir = path.join(root, 'stubs');
    mkdirSync(stubDir);
    for (const [name, body] of Object.entries(STUBS)) {
      writeFileSync(path.join(stubDir, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
    }
    answers.forEach(({ status, out }, i) => {
      writeFileSync(path.join(stubDir, `answer.${i + 1}`), out);
      writeFileSync(path.join(stubDir, `status.${i + 1}`), String(status));
    });

    const prefix = root.replaceAll('\\', '/');
    const script = postinstall
      .replaceAll('/Library/', `${prefix}/Library/`)
      .replaceAll('/usr/local/bin/', `${prefix}/usr/local/bin/`)
      .replaceAll('__COLLECTION_URL__', 'https://baked.example/')
      .replaceAll('__TENANT_ID__', 'tenant-1')
      .replaceAll('__CLIENT_ID__', 'client-1')
      // open-signin runs detached in the package; here it runs in the
      // foreground so its call is logged before the script exits.
      .replace('open-signin >/dev/null 2>&1 &', 'open-signin');
    mkdirSync(path.join(root, 'usr', 'local', 'bin'), { recursive: true });
    writeFileSync(
      path.join(root, 'usr', 'local', 'bin', 'mdmagent'),
      '#!/bin/sh\necho "mdmagent $*" >> "$STUB_DIR/calls.log"\n',
      { mode: 0o755 },
    );
    const scriptPath = path.join(root, 'postinstall');
    writeFileSync(scriptPath, script);

    const childEnv = { ...process.env, ...env, STUB_DIR: stubDir, STUB_CONSOLE_USER: consoleUser };
    delete childEnv.COMMAND_LINE_INSTALL;
    Object.assign(childEnv, env);
    const pathKey = Object.keys(childEnv).find((key) => key.toUpperCase() === 'PATH') ?? 'PATH';
    childEnv[pathKey] = `${stubDir}${path.delimiter}${childEnv[pathKey]}`;

    const result = spawnSync('sh', [scriptPath], { env: childEnv, encoding: 'utf8' });
    strictEqual(result.status, 0, result.stderr);
    const config = JSON.parse(
      readFileSync(path.join(root, 'Library', 'Application Support', 'OfficeHQ', 'MDM', 'config.json'), 'utf8'),
    );
    const callsFile = path.join(stubDir, 'calls.log');
    const calls = existsSync(callsFile) ? lines(readFileSync(callsFile, 'utf8')).filter(Boolean) : [];
    return { config, calls };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const BAKED_CONFIG = {
  collectionUrl: 'https://baked.example/',
  ownership: 'officehq',
  tenantId: 'tenant-1',
  clientId: 'client-1',
  checkInIntervalSeconds: 900,
  logLevel: 'info',
};

for (const consoleUser of ['root', 'loginwindow', '']) {
  test(`postinstall with no console user (${JSON.stringify(consoleUser)}) uses the baked values and asks nothing`, { skip: !HAS_SH && 'no sh' }, () => {
    const { config, calls } = runPostinstall({ consoleUser });
    deepStrictEqual(config, BAKED_CONFIG);
    ok(!calls.some((call) => call.startsWith('osascript') || call.startsWith('mdmagent') || call.startsWith('open')), calls.join('\n'));
    ok(calls.some((call) => call.startsWith('launchctl bootstrap system')));
  });
}

test('postinstall from a command-line install asks nothing even with a console user', { skip: !HAS_SH && 'no sh' }, () => {
  const { config, calls } = runPostinstall({ consoleUser: 'alice', env: { COMMAND_LINE_INSTALL: '1' } });
  deepStrictEqual(config, BAKED_CONFIG);
  ok(!calls.some((call) => call.startsWith('osascript')));
});

test('postinstall asks the console user, re-asks a non-https URL and runs open-signin', { skip: !HAS_SH && 'no sh' }, () => {
  const { config, calls } = runPostinstall({
    consoleUser: 'alice',
    answers: [
      { status: 0, out: 'http://plain.example/' },
      { status: 0, out: 'https://custom.example/' },
      { status: 0, out: 'BYOC (personal device)' },
    ],
  });
  deepStrictEqual(config, { ...BAKED_CONFIG, collectionUrl: 'https://custom.example/', ownership: 'byoc' });

  const asked = calls.filter((call) => call.startsWith('osascript'));
  strictEqual(asked.length, 3);
  // The first dialog defaults to the baked URL; the re-ask to what was typed.
  strictEqual(asked[0], 'osascript https://baked.example/');
  strictEqual(asked[1], 'osascript http://plain.example/');

  const bootstrap = calls.findIndex((call) => call.startsWith('launchctl bootstrap system'));
  const open = calls.indexOf('mdmagent open-signin');
  ok(bootstrap !== -1 && open > bootstrap, calls.join('\n'));
  ok(!calls.some((call) => call.startsWith('open ')), 'the browser is opened by the agent, not postinstall');
});

test('postinstall keeps the baked defaults when the user cancels both questions', { skip: !HAS_SH && 'no sh' }, () => {
  const { config, calls } = runPostinstall({
    consoleUser: 'alice',
    answers: [
      { status: 1, out: '' },
      { status: 0, out: '' },
    ],
  });
  deepStrictEqual(config, BAKED_CONFIG);
  ok(calls.includes('mdmagent open-signin'));
});

test('postinstall picks an OfficeHQ device when the user says so', { skip: !HAS_SH && 'no sh' }, () => {
  const { config } = runPostinstall({
    consoleUser: 'alice',
    answers: [
      { status: 0, out: 'https://baked.example/' },
      { status: 0, out: 'OfficeHQ device' },
    ],
  });
  deepStrictEqual(config, BAKED_CONFIG);
});
