// TASK-065 end-to-end scenarios (Given/When/Then), mirroring the ticket's
// Gherkin feature "The Windows MSI declares service recovery with the WiX
// Util extension and builds without WIX1149 warnings".
//
// No database is involved anywhere in this ticket's scope, so there is
// nothing to mock: these scenarios read the real Product.wxs, build-plan.mjs
// and README.md files on disk, exactly as the real build does, and assert on
// their content. No `cucumber` npm package is used or required; scenarios
// are plain `node --test` cases written in Given/When/Then form.

import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planBuild, wixArgs, WIX_EXTENSIONS } from '../windows/build-plan.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const PRODUCT_WXS = path.join(TEST_DIR, '..', 'windows', 'Product.wxs');
const README = path.join(TEST_DIR, '..', '..', 'README.md');
const WINDOWS_SERVICE_GO = path.join(TEST_DIR, '..', '..', 'agent', 'internal', 'service', 'windows.go');

const ENTITIES = { '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'", '&amp;': '&' };
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

// Given: installers/windows/Product.wxs is parsed with the test file's parseXml
function parseXml(source) {
  const root = { name: '#document', attributes: {}, children: [], text: '' };
  const stack = [root];
  let index = 0;

  while (index < source.length) {
    const open = source.indexOf('<', index);
    if (open === -1) break;

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
    const node = { name, attributes: parseAttributes(body.slice(name.length)), children: [], text: '' };
    stack[stack.length - 1].children.push(node);
    if (!selfClosing) stack.push(node);
  }

  return root;
}

function findAll(node, name) {
  const found = [];
  for (const child of node.children) {
    if (child.name === name) found.push(child);
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
const wixRoot = document.children[0];

// ----------------------------------------------------------------------------
// AC1 (failure/edge: the deprecated core elements must be gone)
// ----------------------------------------------------------------------------
test('Scenario: The deprecated core service-config elements are absent', () => {
  // Then
  strictEqual(findAll(document, 'ServiceConfigFailureActions').length, 0);
  strictEqual(findAll(document, 'Failure').length, 0);
  strictEqual(findAll(document, 'ServiceConfig').length, 0);
});

// ----------------------------------------------------------------------------
// AC2
// ----------------------------------------------------------------------------
test('Scenario: The Wix root declares the util namespace', () => {
  // Then
  strictEqual(wixRoot.name, 'Wix');
  strictEqual(wixRoot.attributes['xmlns:util'], 'http://wixtoolset.org/schemas/v4/wxs/util');
  // And the default namespace stays the core wxs namespace
  strictEqual(wixRoot.attributes.xmlns, 'http://wixtoolset.org/schemas/v4/wxs');
});

// ----------------------------------------------------------------------------
// AC3
// ----------------------------------------------------------------------------
test('Scenario: util:ServiceConfig is nested under the agent service install', () => {
  // Then
  const all = findAll(document, 'util:ServiceConfig');
  strictEqual(all.length, 1);
  const serviceConfig = all[0];

  // And that element is a direct child of ServiceInstall "AgentServiceInstall"
  const install = findOne(document, 'ServiceInstall', (i) => i.attributes.Id === 'AgentServiceInstall');
  ok(install.children.includes(serviceConfig), 'util:ServiceConfig is a direct child of AgentServiceInstall');

  // And ServiceInstall "AgentServiceInstall" is inside Component "AgentExecutable"
  const component = findOne(document, 'Component', (c) => c.attributes.Id === 'AgentExecutable');
  ok(findAll(component, 'ServiceInstall').includes(install), 'AgentServiceInstall is inside AgentExecutable');
});

// ----------------------------------------------------------------------------
// AC4
// ----------------------------------------------------------------------------
test('Scenario: util:ServiceConfig restarts three times after 5 seconds and resets daily', () => {
  // When
  const install = findOne(document, 'ServiceInstall', (i) => i.attributes.Id === 'AgentServiceInstall');
  const serviceConfig = findOne(install, 'util:ServiceConfig');

  // Then
  strictEqual(serviceConfig.attributes.FirstFailureActionType, 'restart');
  strictEqual(serviceConfig.attributes.SecondFailureActionType, 'restart');
  strictEqual(serviceConfig.attributes.ThirdFailureActionType, 'restart');
  strictEqual(serviceConfig.attributes.RestartServiceDelayInSeconds, '5');
  strictEqual(serviceConfig.attributes.ResetPeriodInDays, '1');
});

// AC4 (edge: attributes that would misplace or widen the element)
test('Scenario: util:ServiceConfig names no service and carries no install-timing or command attributes', () => {
  // When
  const install = findOne(document, 'ServiceInstall', (i) => i.attributes.Id === 'AgentServiceInstall');
  const serviceConfig = findOne(install, 'util:ServiceConfig');

  // Then
  for (const name of ['ServiceName', 'ProgramCommandLine', 'RebootMessage', 'OnInstall', 'OnReinstall', 'OnUninstall']) {
    strictEqual(serviceConfig.attributes[name], undefined, `must not carry ${name}`);
  }
});

// ----------------------------------------------------------------------------
// AC5
// ----------------------------------------------------------------------------
test('Scenario: The comment records that the agent owns the failure flag', () => {
  // When the XML comment immediately preceding util:ServiceConfig in the raw source is read
  const elementIndex = source.indexOf('<util:ServiceConfig');
  ok(elementIndex !== -1, 'util:ServiceConfig is present in the raw source');

  const commentStart = source.lastIndexOf('<!--', elementIndex);
  const commentEnd = source.indexOf('-->', commentStart);
  ok(commentStart !== -1 && commentEnd !== -1 && commentEnd < elementIndex, 'a comment precedes the element');
  // "immediately preceding": only whitespace between the comment and the element
  strictEqual(source.slice(commentEnd + '-->'.length, elementIndex).trim(), '');

  const comment = source.slice(commentStart, commentEnd);
  // Then
  ok(comment.includes('EnsureRecovery'), 'comment contains EnsureRecovery');
  ok(comment.includes('failureflag'), 'comment contains failureflag');
});

// ----------------------------------------------------------------------------
// AC6
// ----------------------------------------------------------------------------
for (const arch of ['x64', 'arm64']) {
  test(`Scenario Outline: wix is run with both the UI and Util extensions (arch ${arch})`, () => {
    // Given a plan from planBuild with version "1.2.3", arch and the baked values
    const plan = planBuild({ version: '1.2.3', arch, collectionUrl: 'https://x.example/', tenantId: 'tenant-1', clientId: 'client-1' });
    // When
    const args = wixArgs(plan, '1.2.3');
    const pairs = (flag) => args.flatMap((arg, i) => (arg === flag ? [args[i + 1]] : []));

    // Then
    deepStrictEqual(WIX_EXTENSIONS, ['WixToolset.UI.wixext', 'WixToolset.Util.wixext']);
    deepStrictEqual(pairs('-ext'), ['WixToolset.UI.wixext', 'WixToolset.Util.wixext']);
    // And the -d values are unchanged from before (Version is always first)
    ok(pairs('-d').includes('Version=1.2.3'));
    strictEqual(args[0], 'build');
    deepStrictEqual(args.slice(1, 3), ['-arch', arch]);
  });
}

// ----------------------------------------------------------------------------
// AC7 (failure/edge: regression guard on the surrounding service authoring)
// ----------------------------------------------------------------------------
test('Scenario: The service install and service control are unchanged', () => {
  // Then
  const install = findOne(document, 'ServiceInstall', (i) => i.attributes.Id === 'AgentServiceInstall');
  strictEqual(install.attributes.Name, 'OfficeHQMDMAgent');
  strictEqual(install.attributes.Type, 'ownProcess');
  strictEqual(install.attributes.Start, 'auto');
  strictEqual(install.attributes.Account, 'LocalSystem');
  strictEqual(install.attributes.ErrorControl, 'normal');
  strictEqual(install.attributes.Arguments, 'run');
  strictEqual(install.attributes.Vital, 'yes');

  const control = findOne(document, 'ServiceControl', (c) => c.attributes.Id === 'AgentServiceControl');
  strictEqual(control.attributes.Start, 'install');
  strictEqual(control.attributes.Stop, 'both');
  strictEqual(control.attributes.Remove, 'uninstall');
  strictEqual(control.attributes.Wait, 'yes');
});

// ----------------------------------------------------------------------------
// AC8: the rewritten tests exist and pass is verified by running the full
// `node --test "installers/test/**/*.test.js"` suite (see test report); this
// scenario checks their rewritten shape is in place in the raw source.
// ----------------------------------------------------------------------------
test('Scenario: The rewritten TASK-061 AC14, sign-in and extension tests are in place', () => {
  const msiTestSource = readFileSync(path.join(TEST_DIR, 'windows-msi.test.js'), 'utf8');
  ok(msiTestSource.includes('the MSI declares the service recovery actions nested under the service install'));
  ok(!/xmlns:util.*no Util extension namespace/.test(msiTestSource), 'the xmlns:util assertion was removed from the sign-in test');
  ok(msiTestSource.includes('WixShellExec') && msiTestSource.includes('InternetShortcut') && msiTestSource.includes('/signin'));

  const buildPlanTestSource = readFileSync(path.join(TEST_DIR, 'windows-build-plan.test.js'), 'utf8');
  ok(buildPlanTestSource.includes("WixToolset.UI.wixext', 'WixToolset.Util.wixext"));
});

// ----------------------------------------------------------------------------
// AC9 (manual) -- requires a real `wix build`; exercised by hand by the
// orchestrator/user as the ticket states. Not runnable in this sandboxed
// suite without a real WiX toolchain invocation.
// ----------------------------------------------------------------------------
test('Scenario Outline: A real WiX build emits no warnings (manual, see AC9)', { skip: 'manual: run on a machine with wix + extensions installed' }, () => {});
test('Scenario: A build without the Util extension installed fails instead of silently dropping recovery (manual, see AC9)', { skip: 'manual' }, () => {});

// ----------------------------------------------------------------------------
// AC10 (manual) -- requires an installed MSI and sc.exe on the target
// machine; exercised by hand as the ticket states.
// ----------------------------------------------------------------------------
test('Scenario: The installed service has the recovery actions and the non-crash failure flag (manual, see AC10)', { skip: 'manual: requires a fresh MSI install' }, () => {});

// ----------------------------------------------------------------------------
// AC11
// ----------------------------------------------------------------------------
test('Scenario: The README lists both WiX extensions', () => {
  // When
  const readme = readFileSync(README, 'utf8');
  // Then
  ok(readme.includes('wix extension add -g WixToolset.UI.wixext/5.0.2'));
  ok(readme.includes('wix extension add -g WixToolset.Util.wixext/5.0.2'));
});

// ----------------------------------------------------------------------------
// AC12 -- a true scoped diff of "this ticket's changes" is not computable in
// this working tree (agent/ carries many uncommitted changes from earlier,
// unrelated tickets), so this is a code-review fact plus a regression guard:
// the comment this ticket wrote (AC5) claims the agent's EnsureRecovery sets
// the failure flag with `sc.exe failure` / `sc.exe failureflag`. That claim
// is only true if agent/internal/service/windows.go still issues those
// commands -- if this ticket had touched agent/, breaking or removing them
// would be the observable symptom.
// ----------------------------------------------------------------------------
test('Scenario: The agent code the AC5 comment relies on is untouched by this ticket (verified by review, not diff)', () => {
  const windowsGo = readFileSync(WINDOWS_SERVICE_GO, 'utf8');
  ok(windowsGo.includes('"failure"'), 'windows.go still runs sc.exe failure');
  ok(windowsGo.includes('"failureflag"'), 'windows.go still runs sc.exe failureflag');
});
