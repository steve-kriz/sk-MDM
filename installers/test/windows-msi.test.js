import { test } from 'node:test';
import { ok, strictEqual } from 'node:assert';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const PRODUCT_WXS = path.join(TEST_DIR, '..', 'windows', 'Product.wxs');

const ENTITIES = {
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&apos;': "'",
  '&amp;': '&',
};

function decode(value) {
  return value.replace(/&(?:lt|gt|quot|apos|amp);/g, (entity) => ENTITIES[entity]);
}

function parseAttributes(source) {
  const attributes = {};
  const pattern = /([\w:.-]+)\s*=\s*"([^"]*)"/g;
  let match = pattern.exec(source);
  while (match !== null) {
    attributes[match[1]] = decode(match[2]);
    match = pattern.exec(source);
  }
  return attributes;
}

function findTagEnd(source, start) {
  let quoted = false;
  for (let i = start; i < source.length; i += 1) {
    const char = source[i];
    if (char === '"') {
      quoted = !quoted;
    } else if (char === '>' && !quoted) {
      return i;
    }
  }
  throw new Error(`unterminated tag at offset ${start}`);
}

/**
 * A minimal XML reader: enough for WiX authoring (elements, attributes,
 * self-closing tags, comments, processing instructions and CDATA) and with no
 * dependency, which the repo has none of for tests.
 */
function parseXml(source) {
  const root = { name: '#document', attributes: {}, children: [], text: '' };
  const stack = [root];
  let index = 0;

  while (index < source.length) {
    const open = source.indexOf('<', index);
    if (open === -1) {
      break;
    }

    if (source.startsWith('<!--', open)) {
      index = source.indexOf('-->', open) + 3;
      continue;
    }
    if (source.startsWith('<![CDATA[', open)) {
      const end = source.indexOf(']]>', open);
      stack[stack.length - 1].text += source.slice(open + '<![CDATA['.length, end);
      index = end + 3;
      continue;
    }
    if (source.startsWith('<?', open)) {
      index = source.indexOf('?>', open) + 2;
      continue;
    }

    const close = findTagEnd(source, open);
    const tag = source.slice(open + 1, close);
    index = close + 1;

    if (tag.startsWith('/')) {
      stack.pop();
      continue;
    }

    const selfClosing = tag.endsWith('/');
    const body = selfClosing ? tag.slice(0, -1) : tag;
    const name = /^[^\s/>]+/.exec(body)[0];
    const node = {
      name,
      attributes: parseAttributes(body.slice(name.length)),
      children: [],
      text: '',
    };
    stack[stack.length - 1].children.push(node);
    if (!selfClosing) {
      stack.push(node);
    }
  }

  return root;
}

function findAll(node, name) {
  const found = [];
  for (const child of node.children) {
    if (child.name === name) {
      found.push(child);
    }
    found.push(...findAll(child, name));
  }
  return found;
}

function findOne(node, name, predicate = () => true) {
  const matches = findAll(node, name).filter(predicate);
  strictEqual(matches.length, 1, `expected exactly one ${name}`);
  return matches[0];
}

const source = readFileSync(PRODUCT_WXS, 'utf8');
const document = parseXml(source);
const pkg = findOne(document, 'Package');

test('Product.wxs parses as XML with a Wix root', () => {
  strictEqual(document.children.length, 1);
  strictEqual(document.children[0].name, 'Wix');
});

test('COLLECTIONURL and ENROLLTOKEN are declared as secure properties', () => {
  const properties = findAll(pkg, 'Property');
  for (const id of ['COLLECTIONURL', 'ENROLLTOKEN']) {
    const property = properties.filter((p) => p.attributes.Id === id);
    strictEqual(property.length, 1, `expected one ${id} property`);
    strictEqual(property[0].attributes.Secure, 'yes');
  }
});

test('an empty COLLECTIONURL blocks the install', () => {
  const launch = findOne(pkg, 'Launch');
  strictEqual(launch.attributes.Message, 'COLLECTIONURL is required');
  ok(launch.attributes.Condition.includes('COLLECTIONURL'));
  ok(launch.attributes.Condition.includes('<>'));
  ok(launch.attributes.Condition.includes('""'));
});

test('mdmagent.exe installs into ProgramFiles64Folder\\OfficeHQ\\MDM', () => {
  const programFiles = findOne(
    pkg,
    'StandardDirectory',
    (d) => d.attributes.Id === 'ProgramFiles64Folder',
  );
  const company = findOne(programFiles, 'Directory', (d) => d.attributes.Name === 'OfficeHQ');
  const install = findOne(company, 'Directory', (d) => d.attributes.Name === 'MDM');
  strictEqual(install.attributes.Id, 'INSTALLFOLDER');

  const component = findOne(pkg, 'Component', (c) => c.attributes.Directory === 'INSTALLFOLDER');
  const file = findOne(component, 'File');
  strictEqual(file.attributes.Name, 'mdmagent.exe');
});

test('the agent service is installed as an auto-start LocalSystem service', () => {
  const install = findOne(pkg, 'ServiceInstall');
  strictEqual(install.attributes.Name, 'OfficeHQMDMAgent');
  strictEqual(install.attributes.Start, 'auto');
  strictEqual(install.attributes.Account, 'LocalSystem');
  strictEqual(install.attributes.ErrorControl, 'normal');
});

test('the agent service is started on install and removed on uninstall', () => {
  const control = findOne(pkg, 'ServiceControl');
  strictEqual(control.attributes.Name, 'OfficeHQMDMAgent');
  strictEqual(control.attributes.Start, 'install');
  strictEqual(control.attributes.Stop, 'both');
  strictEqual(control.attributes.Remove, 'uninstall');
});

test('a custom action writes config.json from the install properties', () => {
  const setter = findOne(pkg, 'CustomAction', (a) => a.attributes.Property === 'WriteAgentConfig');
  ok(setter.attributes.Value.includes('[COLLECTIONURL]'));
  ok(setter.attributes.Value.includes('[ENROLLTOKEN]'));
  ok(setter.attributes.Value.includes('[DATAFOLDER]'));

  const writer = findOne(pkg, 'CustomAction', (a) => a.attributes.Id === 'WriteAgentConfig');
  strictEqual(writer.attributes.Execute, 'deferred');
  ok(writer.text.includes('config.json'));
  ok(writer.text.includes('collectionUrl'));
  ok(writer.text.includes('enrollmentToken'));
});

test('the config action is sequenced after InstallFiles and before StartServices', () => {
  const sequence = findOne(pkg, 'InstallExecuteSequence');
  const setter = findOne(sequence, 'Custom', (c) => c.attributes.Action === 'SetWriteAgentConfigData');
  strictEqual(setter.attributes.After, 'InstallFiles');

  const writer = findOne(sequence, 'Custom', (c) => c.attributes.Action === 'WriteAgentConfig');
  strictEqual(writer.attributes.Before, 'StartServices');
});

test('uninstall removes the ProgramData config and data directory', () => {
  const commonAppData = findOne(
    pkg,
    'StandardDirectory',
    (d) => d.attributes.Id === 'CommonAppDataFolder',
  );
  const company = findOne(commonAppData, 'Directory', (d) => d.attributes.Name === 'OfficeHQ');
  const data = findOne(company, 'Directory', (d) => d.attributes.Name === 'MDM');
  strictEqual(data.attributes.Id, 'DATAFOLDER');

  const component = findOne(pkg, 'Component', (c) => c.attributes.Directory === 'DATAFOLDER');
  const removedFiles = findAll(component, 'RemoveFile');
  ok(removedFiles.some((f) => f.attributes.Name === 'config.json'));
  for (const removed of removedFiles) {
    strictEqual(removed.attributes.On, 'uninstall');
  }

  const removedFolders = findAll(component, 'RemoveFolder');
  ok(removedFolders.length > 0);
  for (const removed of removedFolders) {
    strictEqual(removed.attributes.On, 'uninstall');
  }
});

test('the package declares a fixed UpgradeCode and a major upgrade', () => {
  ok(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(pkg.attributes.UpgradeCode));

  const upgrade = findOne(pkg, 'MajorUpgrade');
  strictEqual(upgrade.attributes.AllowSameVersionUpgrades, 'yes');
  ok(upgrade.attributes.DowngradeErrorMessage.length > 0);
});
