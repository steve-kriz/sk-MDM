/**
 * Tests that the Lambda code asset (`dist`) loads as ES modules on its own.
 *
 * The asset is `dist` alone, so `backend/package.json` is not shipped; without
 * `dist/package.json` the Lambda runtime fails at init with
 * "Cannot use import statement outside a module".
 */

import test from 'node:test';
import assert from 'node:assert';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dist = path.resolve(__dirname, '../../dist');

test('Scenario: the built asset declares itself an ES module package', () => {
  // Given the backend has been built
  // When dist/package.json is read
  const pkg = JSON.parse(readFileSync(path.join(dist, 'package.json'), 'utf-8'));

  // Then its type is module
  assert.strictEqual(pkg.type, 'module');
});

test('Scenario: the handler loads the way the Lambda runtime loads it', (t) => {
  // Given only the dist directory, copied outside the backend package as the Lambda receives it
  const task = mkdtempSync(path.join(tmpdir(), 'mdm-asset-'));
  t.after(() => rmSync(task, { recursive: true, force: true }));
  cpSync(dist, task, { recursive: true, filter: (src) => !src.includes(`${path.sep}infra`) });

  // When index.js is imported with module-syntax detection off, as the Lambda
  // runtime does -- local Node 22 would otherwise sniff the ESM syntax and hide
  // a missing "type": "module"
  const indexUrl = pathToFileURL(path.join(task, 'index.js')).href;
  const result = spawnSync(
    process.execPath,
    ['--no-experimental-detect-module', '-e',`import(${JSON.stringify(indexUrl)}).then((m) => { if (typeof m.handler !== 'function') process.exit(3); })`],
    { cwd: task, encoding: 'utf-8' },
  );

  // Then it loads as ESM without a syntax error and exports a handler function
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(!result.stderr.includes('Failed to load the ES module'), result.stderr);
});
