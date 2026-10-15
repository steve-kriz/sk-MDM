import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual } from 'node:assert';
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

/** The Package-level Property with this Id. */
const property = (id) => findOne(pkg, 'Property', (p) => p.attributes.Id === id);

test('the install values are declared as public secure properties', () => {
  for (const id of ['COLLECTIONURL', 'OWNERSHIP', 'TENANTID', 'CLIENTID', 'ENROLLTOKEN']) {
    strictEqual(property(id).attributes.Secure, 'yes', `${id} is secure`);
  }
});

test('the baked packaging values are the property defaults', () => {
  strictEqual(property('COLLECTIONURL').attributes.Value, '$(var.DefaultCollectionUrl)');
  strictEqual(property('TENANTID').attributes.Value, '$(var.TenantId)');
  strictEqual(property('CLIENTID').attributes.Value, '$(var.ClientId)');
  // A silent install with no OWNERSHIP records an OfficeHQ device.
  strictEqual(property('OWNERSHIP').attributes.Value, 'officehq');
  // The legacy token stays optional: no default.
  strictEqual(property('ENROLLTOKEN').attributes.Value, undefined);
});

test('a build without the packaging variables is refused by the preprocessor', () => {
  for (const name of ['DefaultCollectionUrl', 'TenantId', 'ClientId']) {
    ok(source.includes(`<?ifndef ${name} ?>`), `${name} is checked`);
  }
});

test('an empty COLLECTIONURL blocks the install', () => {
  const launch = findOne(pkg, 'Launch', (l) => l.attributes.Message === 'COLLECTIONURL is required');
  ok(launch.attributes.Condition.includes('COLLECTIONURL'));
  ok(launch.attributes.Condition.includes('<>'));
  ok(launch.attributes.Condition.includes('""'));
});

test('an OWNERSHIP other than officehq or byoc blocks the install', () => {
  const launch = findOne(pkg, 'Launch', (l) => l.attributes.Message === 'OWNERSHIP must be officehq or byoc');
  strictEqual(launch.attributes.Condition, 'OWNERSHIP = "officehq" OR OWNERSHIP = "byoc"');
});

const ui = findOne(document, 'UI', (u) => u.attributes.Id === 'OfficeHQ_UI');
const settings = findOne(ui, 'Dialog', (d) => d.attributes.Id === 'OfficeHQSettingsDlg');
const control = (id) => findOne(settings, 'Control', (c) => c.attributes.Id === id);
const publishes = (dialog, controlId) =>
  findAll(ui, 'Publish').filter((p) => p.attributes.Dialog === dialog && p.attributes.Control === controlId);

test('the package uses the OfficeHQ wizard built on WixUI_Common', () => {
  findOne(pkg, 'UIRef', (r) => r.attributes.Id === 'OfficeHQ_UI');
  findOne(document, 'UIRef', (r) => r.attributes.Id === 'WixUI_Common');
});

test('the settings dialog follows Welcome and precedes VerifyReady', () => {
  const welcomeNext = publishes('WelcomeDlg', 'Next').find((p) => p.attributes.Condition === 'NOT Installed');
  strictEqual(welcomeNext.attributes.Value, 'OfficeHQSettingsDlg');
  strictEqual(publishes('OfficeHQSettingsDlg', 'Next')[0].attributes.Value, 'VerifyReadyDlg');
  strictEqual(publishes('OfficeHQSettingsDlg', 'Back')[0].attributes.Value, 'WelcomeDlg');
  const readyBack = publishes('VerifyReadyDlg', 'Back').find((p) => p.attributes.Condition === 'NOT Installed');
  strictEqual(readyBack.attributes.Value, 'OfficeHQSettingsDlg');
});

test('the settings dialog edits COLLECTIONURL and picks OWNERSHIP', () => {
  const edit = control('CollectionUrlEdit');
  strictEqual(edit.attributes.Type, 'Edit');
  strictEqual(edit.attributes.Property, 'COLLECTIONURL');

  const group = control('OwnershipGroup');
  strictEqual(group.attributes.Type, 'RadioButtonGroup');
  strictEqual(group.attributes.Property, 'OWNERSHIP');
  const buttons = findAll(group, 'RadioButton').map((b) => [b.attributes.Value, b.attributes.Text]);
  deepStrictEqual(buttons, [
    ['officehq', 'OfficeHQ device'],
    ['byoc', 'BYOC (personal device)'],
  ]);
});

test('Next is disabled until the collection URL starts with https://', () => {
  const next = control('Next');
  strictEqual(next.attributes.EnableCondition, 'COLLECTIONURL << "https://"');
  strictEqual(next.attributes.DisableCondition, 'NOT (COLLECTIONURL << "https://")');
  strictEqual(publishes('OfficeHQSettingsDlg', 'Next')[0].attributes.Condition, 'COLLECTIONURL << "https://"');
});

test('the wizard shows the OfficeHQ branded bitmaps', () => {
  const variable = (id) => findOne(pkg, 'WixVariable', (v) => v.attributes.Id === id).attributes.Value;
  strictEqual(variable('WixUIBannerBmp'), '$(sys.SOURCEFILEDIR)..\\branding\\banner.bmp');
  strictEqual(variable('WixUIDialogBmp'), '$(sys.SOURCEFILEDIR)..\\branding\\dialog.bmp');
});

test('the exit dialog offers to sign in, checked by default, by running mdmagent open-signin', () => {
  strictEqual(property('WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT').attributes.Value, 'Sign in to OfficeHQ MDM now');
  strictEqual(property('WIXUI_EXITDIALOGOPTIONALCHECKBOX').attributes.Value, '1');

  const action = findOne(pkg, 'CustomAction', (a) => a.attributes.Id === 'OpenSignInPage');
  // "[INSTALLFOLDER]mdmagent.exe" open-signin, as the user, without waiting.
  strictEqual(action.attributes.FileRef, 'mdmagent.exe');
  strictEqual(action.attributes.ExeCommand, 'open-signin');
  strictEqual(action.attributes.Impersonate, 'yes');
  strictEqual(action.attributes.Return, 'asyncNoWait');
  strictEqual(action.attributes.DllEntry, undefined);
  strictEqual(action.attributes.BinaryRef, undefined);
  findOne(pkg, 'File', (f) => f.attributes.Id === 'mdmagent.exe');

  const finish = publishes('ExitDialog', 'Finish').find((p) => p.attributes.Value === 'OpenSignInPage');
  strictEqual(finish.attributes.Event, 'DoAction');
  strictEqual(finish.attributes.Condition, 'WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 AND NOT Installed');
});

test('the sign-in goes through the agent, not WixShellExec or a loopback URL', () => {
  ok(!source.includes('WixShellExec'), 'no WixShellExec');
  ok(!source.includes('InternetShortcut'), 'no internet shortcut');
  ok(!source.includes('/signin'), 'no sign-in URL: the agent finds it');
});

test('a Start-menu shortcut runs mdmagent open-signin', () => {
  const component = findOne(pkg, 'Component', (c) => c.attributes.Id === 'SignInShortcut');
  strictEqual(component.attributes.Directory, 'ProgramMenuFolder');
  const shortcut = findOne(component, 'Shortcut');
  strictEqual(shortcut.attributes.Name, 'Sign in to OfficeHQ MDM');
  strictEqual(shortcut.attributes.Target, '[INSTALLFOLDER]mdmagent.exe');
  strictEqual(shortcut.attributes.Arguments, 'open-signin');
  // The Start menu is a per-user location, so the key path is an HKCU value
  // (ICE38). The shortcut sits directly in ProgramMenuFolder, which is not
  // ours to remove, so there is no RemoveFolder.
  const key = findOne(component, 'RegistryValue');
  strictEqual(key.attributes.Root, 'HKCU');
  strictEqual(key.attributes.KeyPath, 'yes');
  strictEqual(findAll(component, 'RemoveFolder').length, 0);
  // Owned by a component of the installed feature, so uninstall removes it.
  ok(findAll(findOne(pkg, 'ComponentGroup'), 'Component').includes(component));
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
  strictEqual(
    setter.attributes.Value,
    '[DATAFOLDER]|[COLLECTIONURL]|[OWNERSHIP]|[TENANTID]|[CLIENTID]|[ENROLLTOKEN]',
  );

  const writer = findOne(pkg, 'CustomAction', (a) => a.attributes.Id === 'WriteAgentConfig');
  strictEqual(writer.attributes.Execute, 'deferred');
  // WiX v4+ refuses inline script: the JScript lives beside Product.wxs.
  strictEqual(writer.attributes.Script, 'jscript');
  strictEqual(writer.attributes.ScriptSourceFile, '$(sys.SOURCEFILEDIR)write-config.js');
  strictEqual(writer.text.trim(), '');
  const script = readFileSync(path.join(TEST_DIR, '..', 'windows', 'write-config.js'), 'utf8');
  ok(script.includes('config.json'));
  for (const key of ['collectionUrl', 'ownership', 'tenantId', 'clientId', 'enrollmentToken']) {
    ok(script.includes(key), `write-config.js writes ${key}`);
  }
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

// ----------------------------------------------------------------------------
// TASK-061 AC14: the agent never restarts itself -- the MSI declares the
// service's recovery actions nested under the service install, so the SCM
// restarts it after a self-update or a crash. TASK-065: declared with the
// WixToolset.Util.wixext util:ServiceConfig instead of the deprecated core
// elements (WIX1149).
// ----------------------------------------------------------------------------
test('Scenario: the MSI declares the service recovery actions nested under the service install', () => {
  // Given installers/windows/Product.wxs is parsed
  const install = findOne(pkg, 'ServiceInstall', (i) => i.attributes.Id === 'AgentServiceInstall');

  // Then the deprecated core service-config elements are absent everywhere
  strictEqual(findAll(document, 'ServiceConfigFailureActions').length, 0);
  strictEqual(findAll(document, 'Failure').length, 0);
  strictEqual(findAll(document, 'ServiceConfig').length, 0);

  // And the document has exactly one util:ServiceConfig, a direct child of
  // ServiceInstall "AgentServiceInstall"
  const all = findAll(document, 'util:ServiceConfig');
  strictEqual(all.length, 1);
  const serviceConfig = all[0];
  ok(install.children.includes(serviceConfig), 'util:ServiceConfig is a direct child of AgentServiceInstall');

  // And it restarts three times after 5 seconds and resets the count daily
  strictEqual(serviceConfig.attributes.FirstFailureActionType, 'restart');
  strictEqual(serviceConfig.attributes.SecondFailureActionType, 'restart');
  strictEqual(serviceConfig.attributes.ThirdFailureActionType, 'restart');
  strictEqual(serviceConfig.attributes.RestartServiceDelayInSeconds, '5');
  strictEqual(serviceConfig.attributes.ResetPeriodInDays, '1');

  // And it names no service and carries no install-timing or command attributes
  for (const name of ['ServiceName', 'ProgramCommandLine', 'RebootMessage', 'OnInstall', 'OnReinstall', 'OnUninstall']) {
    strictEqual(serviceConfig.attributes[name], undefined, `util:ServiceConfig must not carry ${name}`);
  }
});

// AC2: the Wix root declares the util namespace, and keeps the default wxs namespace.
test('the Wix root declares xmlns:util and keeps the default wxs namespace', () => {
  const wixRoot = document.children[0];
  strictEqual(wixRoot.name, 'Wix');
  strictEqual(wixRoot.attributes['xmlns:util'], 'http://wixtoolset.org/schemas/v4/wxs/util');
  strictEqual(wixRoot.attributes.xmlns, 'http://wixtoolset.org/schemas/v4/wxs');
});

// AC5: the comment immediately before util:ServiceConfig records why the
// agent, not util:ServiceConfig, sets the non-crash failure flag.
// parseXml discards comments, so this reads the raw source directly.
test('the comment directly before util:ServiceConfig mentions EnsureRecovery and failureflag', () => {
  const elementIndex = source.indexOf('<util:ServiceConfig');
  ok(elementIndex !== -1, 'util:ServiceConfig is present');

  const commentStart = source.lastIndexOf('<!--', elementIndex);
  const commentEnd = source.indexOf('-->', commentStart);
  ok(commentStart !== -1 && commentEnd !== -1 && commentEnd < elementIndex, 'a comment precedes the element');
  strictEqual(source.slice(commentEnd + '-->'.length, elementIndex).trim(), '', 'nothing but whitespace sits between the comment and the element');

  const comment = source.slice(commentStart, commentEnd);
  ok(comment.includes('EnsureRecovery'), 'comment mentions EnsureRecovery');
  ok(comment.includes('failureflag'), 'comment mentions failureflag');

  // Edge: the new/updated comments must not reintroduce sign-in strings.
  ok(!comment.includes('WixShellExec'));
  ok(!comment.includes('InternetShortcut'));
  ok(!comment.includes('/signin'));
});

// AC7: the rest of ServiceInstall/ServiceControl keeps every value it had
// before (regression guard; the two existing tests above only check a subset).
test('ServiceInstall and ServiceControl keep their type, arguments, vital and wait settings', () => {
  const install = findOne(pkg, 'ServiceInstall', (i) => i.attributes.Id === 'AgentServiceInstall');
  strictEqual(install.attributes.Name, 'OfficeHQMDMAgent');
  strictEqual(install.attributes.Type, 'ownProcess');
  strictEqual(install.attributes.Start, 'auto');
  strictEqual(install.attributes.Account, 'LocalSystem');
  strictEqual(install.attributes.ErrorControl, 'normal');
  strictEqual(install.attributes.Arguments, 'run');
  strictEqual(install.attributes.Vital, 'yes');

  const control = findOne(pkg, 'ServiceControl', (c) => c.attributes.Id === 'AgentServiceControl');
  strictEqual(control.attributes.Start, 'install');
  strictEqual(control.attributes.Stop, 'both');
  strictEqual(control.attributes.Remove, 'uninstall');
  strictEqual(control.attributes.Wait, 'yes');
});

// AC11: README documents both WiX extensions needed to build the installer.
test('README documents the UI and Util wix extensions', () => {
  const readme = readFileSync(path.join(TEST_DIR, '..', '..', 'README.md'), 'utf8');
  ok(readme.includes('wix extension add -g WixToolset.UI.wixext/5.0.2'));
  ok(readme.includes('wix extension add -g WixToolset.Util.wixext/5.0.2'));
});

// AC12 (code-review guard, not a diff): the AC5 comment's claim is only true
// if the agent still issues these sc.exe sub-commands. A scoped git diff of
// "this ticket's changes" is not computable here because agent/ carries many
// uncommitted changes from unrelated, earlier tickets on this branch.
test('the agent still runs the sc.exe failure and failureflag commands the AC5 comment relies on', () => {
  const windowsGo = readFileSync(
    path.join(TEST_DIR, '..', '..', 'agent', 'internal', 'service', 'windows.go'),
    'utf8',
  );
  ok(windowsGo.includes('"failure"'));
  ok(windowsGo.includes('"failureflag"'));
});

test('the package declares a fixed UpgradeCode and a major upgrade', () => {
  ok(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(pkg.attributes.UpgradeCode));

  const upgrade = findOne(pkg, 'MajorUpgrade');
  strictEqual(upgrade.attributes.AllowSameVersionUpgrades, 'yes');
  ok(upgrade.attributes.DowngradeErrorMessage.length > 0);
});
