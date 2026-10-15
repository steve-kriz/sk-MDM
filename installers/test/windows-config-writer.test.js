import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import {
  renderConfig,
  validateCollectionUrl,
  CHECK_IN_INTERVAL_SECONDS,
  LOG_LEVEL,
  COLLECTION_URL_ERROR,
  OWNERSHIP_ERROR,
} from '../windows/config-writer.mjs';

const MESSAGE = 'collection url must be an https url';
const WRITE_CONFIG = fileURLToPath(new URL('../windows/write-config.js', import.meta.url));

const FULL = {
  collectionUrl: 'https://x.example/',
  ownership: 'byoc',
  tenantId: 'tenant-1',
  clientId: 'client-1',
};

/**
 * Runs write-config.js the way the MSI's JScript host does, with a fake
 * Session and FileSystemObject, and returns { path, text } of the file written.
 */
function runWriteConfig(customActionData) {
  const written = {};
  const created = [];
  const fso = {
    FolderExists: () => false,
    GetParentFolderName: (dir) => dir.replace(/\\[^\\]*$/, ''),
    CreateFolder: (dir) => created.push(dir),
    BuildPath: (dir, name) => `${dir}\\${name}`,
    CreateTextFile: (file) => ({
      Write: (text) => {
        written.path = file;
        written.text = text;
      },
      Close: () => {},
    }),
  };
  const context = {
    Session: { Property: (name) => (name === 'CustomActionData' ? customActionData : '') },
    ActiveXObject: function ActiveXObject(progId) {
      strictEqual(progId, 'Scripting.FileSystemObject');
      return fso;
    },
  };
  vm.runInNewContext(readFileSync(WRITE_CONFIG, 'utf8'), context);
  return { ...written, created };
}

test('the refusal message matches agent/internal/config', () => {
  strictEqual(COLLECTION_URL_ERROR, MESSAGE);
});

test('renderConfig writes the URL, ownership, tenant, client and defaults', () => {
  const parsed = JSON.parse(renderConfig(FULL));
  deepStrictEqual(parsed, {
    collectionUrl: 'https://x.example/',
    ownership: 'byoc',
    tenantId: 'tenant-1',
    clientId: 'client-1',
    checkInIntervalSeconds: 900,
    logLevel: 'info',
  });
});

test('renderConfig writes no enrollmentToken unless one is given', () => {
  ok(!('enrollmentToken' in JSON.parse(renderConfig(FULL))));
  ok(!('enrollmentToken' in JSON.parse(renderConfig({ ...FULL, enrollToken: '' }))));
  strictEqual(JSON.parse(renderConfig({ ...FULL, enrollToken: 't1' })).enrollmentToken, 't1');
});

test('renderConfig defaults ownership to officehq and refuses anything else', () => {
  strictEqual(JSON.parse(renderConfig({ collectionUrl: 'https://x.example/' })).ownership, 'officehq');
  strictEqual(JSON.parse(renderConfig({ ...FULL, ownership: '' })).ownership, 'officehq');
  strictEqual(JSON.parse(renderConfig({ ...FULL, ownership: 'officehq' })).ownership, 'officehq');
  throws(() => renderConfig({ ...FULL, ownership: 'personal' }), { message: OWNERSHIP_ERROR });
});

test('renderConfig omits an empty tenant or client', () => {
  const parsed = JSON.parse(renderConfig({ collectionUrl: 'https://x.example/', tenantId: '', clientId: '' }));
  ok(!('tenantId' in parsed));
  ok(!('clientId' in parsed));
});

test('the defaults are the ones the agent applies', () => {
  strictEqual(CHECK_IN_INTERVAL_SECONDS, 900);
  strictEqual(LOG_LEVEL, 'info');
});

test('renderConfig returns a JSON string ending in a newline', () => {
  const rendered = renderConfig(FULL);
  strictEqual(typeof rendered, 'string');
  ok(rendered.endsWith('\n'));
});

test('renderConfig refuses an empty or absent collection URL', () => {
  throws(() => renderConfig({ ...FULL, collectionUrl: '' }), { message: MESSAGE });
  throws(() => renderConfig({ ownership: 'byoc' }), { message: MESSAGE });
  throws(() => renderConfig(), { message: MESSAGE });
});

test('renderConfig refuses an unparseable or non-https collection URL', () => {
  for (const collectionUrl of ['not a url', 'http://x.example/', 'file:///tmp/x']) {
    throws(() => renderConfig({ ...FULL, collectionUrl }), { message: MESSAGE });
  }
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
      throws(() => renderConfig({ ...FULL, collectionUrl }), { message: MESSAGE });
    }
    deepStrictEqual(readdirSync(directory), []);
  } finally {
    process.chdir(previous);
    rmSync(directory, { recursive: true, force: true });
  }
});

test('write-config.js writes config.json into the data directory from CustomActionData', () => {
  const result = runWriteConfig('C:\\ProgramData\\OfficeHQ\\MDM|https://x.example/|byoc|tenant-1|client-1|');
  strictEqual(result.path, 'C:\\ProgramData\\OfficeHQ\\MDM\\config.json');
  ok(result.text.includes('\r\n'), 'the file uses Windows line endings');
  deepStrictEqual(JSON.parse(result.text), JSON.parse(renderConfig(FULL)));
});

test('write-config.js matches renderConfig with and without the optional values', () => {
  const cases = [
    [{ ...FULL, ownership: 'officehq' }, 'D|https://x.example/|officehq|tenant-1|client-1|'],
    [{ ...FULL, enrollToken: 't1' }, 'D|https://x.example/|byoc|tenant-1|client-1|t1'],
    [{ ...FULL, enrollToken: 'a|b"c\\d' }, 'D|https://x.example/|byoc|tenant-1|client-1|a|b"c\\d'],
    [{ collectionUrl: 'https://x.example/' }, 'D|https://x.example/||||'],
  ];
  for (const [input, data] of cases) {
    deepStrictEqual(JSON.parse(runWriteConfig(data).text), JSON.parse(renderConfig(input)), data);
  }
});
