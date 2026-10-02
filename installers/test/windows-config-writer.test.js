import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  renderConfig,
  validateCollectionUrl,
  CHECK_IN_INTERVAL_SECONDS,
  LOG_LEVEL,
  COLLECTION_URL_ERROR,
} from '../windows/config-writer.mjs';

const MESSAGE = 'collection url must be an https url';

test('the refusal message matches agent/internal/config', () => {
  strictEqual(COLLECTION_URL_ERROR, MESSAGE);
});

test('renderConfig produces exactly the four keys Load reads', () => {
  const rendered = renderConfig({ collectionUrl: 'https://x.example/', enrollToken: 't1' });
  const parsed = JSON.parse(rendered);
  deepStrictEqual(Object.keys(parsed).sort(), [
    'checkInIntervalSeconds',
    'collectionUrl',
    'enrollmentToken',
    'logLevel',
  ]);
  strictEqual(parsed.collectionUrl, 'https://x.example/');
  strictEqual(parsed.enrollmentToken, 't1');
  strictEqual(parsed.checkInIntervalSeconds, 900);
  strictEqual(parsed.logLevel, 'info');
});

test('the defaults are the ones the agent applies', () => {
  strictEqual(CHECK_IN_INTERVAL_SECONDS, 900);
  strictEqual(LOG_LEVEL, 'info');
});

test('renderConfig returns a JSON string ending in a newline', () => {
  const rendered = renderConfig({ collectionUrl: 'https://x.example/', enrollToken: 't1' });
  strictEqual(typeof rendered, 'string');
  ok(rendered.endsWith('\n'));
});

test('renderConfig refuses an empty collection URL', () => {
  throws(() => renderConfig({ collectionUrl: '', enrollToken: 't1' }), { message: MESSAGE });
});

test('renderConfig refuses an absent collection URL', () => {
  throws(() => renderConfig({ enrollToken: 't1' }), { message: MESSAGE });
  throws(() => renderConfig(), { message: MESSAGE });
});

test('renderConfig refuses an unparseable collection URL', () => {
  throws(() => renderConfig({ collectionUrl: 'not a url', enrollToken: 't1' }), { message: MESSAGE });
});

test('renderConfig refuses a non-https collection URL', () => {
  throws(() => renderConfig({ collectionUrl: 'http://x.example/', enrollToken: 't1' }), {
    message: MESSAGE,
  });
  throws(() => renderConfig({ collectionUrl: 'file:///tmp/x', enrollToken: 't1' }), {
    message: MESSAGE,
  });
});

test('validateCollectionUrl accepts an https URL', () => {
  validateCollectionUrl('https://x.example/');
});

test('a refused collection URL writes no file', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'mdm-config-writer-'));
  const previous = process.cwd();
  process.chdir(directory);
  try {
    for (const collectionUrl of ['', undefined, 'not a url', 'http://x.example/']) {
      throws(() => renderConfig({ collectionUrl, enrollToken: 't1' }), { message: MESSAGE });
    }
    deepStrictEqual(readdirSync(directory), []);
  } finally {
    process.chdir(previous);
    rmSync(directory, { recursive: true, force: true });
  }
});
