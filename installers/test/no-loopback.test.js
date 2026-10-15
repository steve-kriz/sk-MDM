import { test } from 'node:test';
import { deepStrictEqual } from 'node:assert';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Sign-in is brokered by the MDM site (spec Amendment A): nothing the
// installers, the packaging scripts or the packaging docs ship may still point
// at the agent's old loopback listener. The pattern is assembled so this file
// does not match itself.

const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const LOOPBACK = new RegExp(`${['local', 'host'].join('')}|${String(47_615)}`, 'i');
const SKIP = new Set(['node_modules', 'build', 'dist']);
const BINARY = /\.(bmp|png|ico|msi|pkg|wixpdb|exe)$/i;

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      return SKIP.has(name) ? [] : files(full);
    }
    return BINARY.test(name) ? [] : [full];
  });
}

test('no loopback sign-in address remains in installers/ or scripts/', () => {
  const scanned = [
    ...files(path.join(REPO, 'installers')),
    ...files(path.join(REPO, 'scripts')),
  ];
  const offenders = scanned
    .filter((file) => LOOPBACK.test(readFileSync(file, 'utf8')))
    .map((file) => path.relative(REPO, file));
  deepStrictEqual(offenders, []);
});
