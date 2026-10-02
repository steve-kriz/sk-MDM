/**
 * One device in full: the sections `GET /admin/api/v1/devices/{deviceId}`
 * answers with.
 *
 *   render({profile, inventory, posture, commands, antivirusFindings})
 *
 * Every section is rendered even when the device has never reported one, so a
 * machine that is enrolled but silent looks different from one that is
 * missing: the heading is there, with nothing under it.
 */
import { cell, escapeHtml } from '../public/html.js';

/** The command columns a row shows, in order. */
export const COMMAND_COLUMNS = ['commandId', 'type', 'status', 'issuedAt'];

/** The antivirus finding columns a row shows, in order. */
export const FINDING_COLUMNS = ['detectedAt', 'threatName', 'severity', 'remediated', 'resources'];

/** A nested value (`inventory.hardware.serialNumber`), or `null` when any step is missing. */
function at(source, path) {
  let value = source;
  for (const key of path) {
    if (value === null || value === undefined || typeof value !== 'object') {
      return null;
    }
    value = value[key];
  }
  return value ?? null;
}

/** `true`/`false`/unknown, as a word rather than a checkbox. */
function flag(value) {
  if (value === true) {
    return 'true';
  }
  if (value === false) {
    return 'false';
  }
  return 'unknown';
}

/** A definition row inside a section. */
function field(label, value) {
  return `<div class="field"><span class="label">${escapeHtml(label)}</span><span class="value">${value}</span></div>`;
}

/** One queued or finished command. */
function commandRow(command) {
  const cells = COMMAND_COLUMNS.map((column) => `<td class="col-${column}">${cell(command[column])}</td>`).join('');
  return `<tr class="command" data-command-id="${escapeHtml(command.commandId)}">${cells}</tr>`;
}

/** One antivirus threat detection; `resources` is shown joined with `, `. */
function findingRow(entry) {
  const finding = entry ?? {};
  const values = {
    ...finding,
    remediated: flag(finding.remediated),
    resources: Array.isArray(finding.resources) ? finding.resources.join(', ') : finding.resources,
  };
  const cells = FINDING_COLUMNS.map((column) => `<td class="col-${column}">${cell(values[column])}</td>`).join('');
  return `<tr class="antivirus-finding">${cells}</tr>`;
}

/** The device detail screen. */
export function render(state = {}) {
  const profile = state.profile ?? {};
  const inventory = state.inventory ?? null;
  const posture = state.posture ?? null;
  const commands = Array.isArray(state.commands) ? state.commands : [];
  const findings = Array.isArray(state.antivirusFindings) ? state.antivirusFindings : [];
  const software = at(inventory, ['software']);
  const softwareCount = Array.isArray(software) ? software.length : 0;

  const profileSection = [
    '<section class="panel" id="detail-profile"><h3>Profile</h3>',
    field('hostname', cell(profile.hostname)),
    field('platform', cell(profile.platform)),
    field('osVersion', cell(profile.osVersion)),
    field('lastSeenAt', cell(profile.lastSeenAt)),
    field('complianceState', cell(profile.complianceState)),
    '</section>',
  ].join('');

  const inventorySection = [
    '<section class="panel" id="detail-inventory"><h3>Inventory</h3>',
    field('serialNumber', cell(at(inventory, ['hardware', 'serialNumber']))),
    field('os.version', cell(at(inventory, ['os', 'version']))),
    field('software', `${softwareCount} installed`),
    '</section>',
  ].join('');

  const postureSection = [
    '<section class="panel" id="detail-posture"><h3>Posture</h3>',
    field('diskEncryption.enabled', flag(at(posture, ['diskEncryption', 'enabled']))),
    field('firewall.enabled', flag(at(posture, ['firewall', 'enabled']))),
    field('antivirus.enabled', flag(at(posture, ['antivirus', 'enabled']))),
    '</section>',
  ].join('');

  const commandsSection = [
    '<section class="panel" id="detail-commands"><h3>Commands</h3>',
    commands.length === 0
      ? '<p class="empty">No commands issued</p>'
      : [
          '<table class="grid commands">',
          `<thead><tr>${COMMAND_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${commands.map(commandRow).join('')}</tbody>`,
          '</table>',
        ].join(''),
    '</section>',
  ].join('');

  const findingsSection = [
    '<section class="panel" id="detail-antivirus-findings"><h3>Antivirus findings</h3>',
    findings.length === 0
      ? '<p class="empty">No antivirus findings</p>'
      : [
          '<table class="grid antivirus-findings">',
          `<thead><tr>${FINDING_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${findings.map(findingRow).join('')}</tbody>`,
          '</table>',
        ].join(''),
    '</section>',
  ].join('');

  return [
    `<section class="screen" id="screen-device-detail" data-device-id="${escapeHtml(profile.deviceId ?? state.deviceId)}">`,
    `<h2>${cell(profile.hostname ?? profile.deviceId ?? state.deviceId)}</h2>`,
    profileSection,
    inventorySection,
    postureSection,
    commandsSection,
    findingsSection,
    '</section>',
  ].join('');
}

export const renderDeviceDetail = render;
