import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Everything here is a file-text assertion: pkgbuild, productbuild, productsign
// and launchctl exist on macOS only, so the package's behaviour is pinned by
// what the shipped scripts say rather than by running them. Nothing in this
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
    .replaceAll('__COLLECTION_URL__', 'https://x.example/')
    .replaceAll('__ENROLL_TOKEN__', 't1');

  const config = JSON.parse(body);
  deepStrictEqual(config, {
    collectionUrl: 'https://x.example/',
    enrollmentToken: 't1',
    checkInIntervalSeconds: 900,
    logLevel: 'info',
  });
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
  for (const flag of ['--version', '--arch', '--collection-url', '--enroll-token']) {
    ok(line.includes(flag), `build.sh forwards ${flag}`);
  }
});

test('build.sh substitutes both config placeholders', () => {
  const sed = lines(buildSh).find((line) => line.startsWith('sed '));
  ok(sed !== undefined, 'build.sh runs sed over the postinstall script');
  ok(sed.includes('__COLLECTION_URL__'), 'sed substitutes the collection URL');
  ok(sed.includes('__ENROLL_TOKEN__'), 'sed substitutes the enrolment token');
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
