/**
 * One device in full: the four sections `GET /admin/api/v1/devices/{deviceId}`
 * answers with.
 *
 *   render({profile, inventory, posture, commands})
 *
 * Every section is rendered even when the device has never reported one, so a
 * machine that is enrolled but silent looks different from one that is
 * missing: the heading is there, with nothing under it.
 */
import { cell, escapeHtml } from '../public/html.js';

/** The command columns a row shows, in order. */
export const COMMAND_COLUMNS = ['commandId', 'type', 'status', 'issuedAt'];

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

/** One registered user of the device. */
function userRow(user) {
  return [
    '<tr class="user">',
    `<td class="col-displayName">${cell(user?.displayName)}</td>`,
    `<td class="col-userPrincipalName">${cell(user?.userPrincipalName)}</td>`,
    '</tr>',
  ].join('');
}

/** The Entra user(s) linked to the device, and the button that re-resolves them. */
function userSection(userLink, deviceId) {
  const button = `<button type="button" class="refresh-user-link" data-device-id="${escapeHtml(deviceId)}">Refresh user link</button>`;
  if (userLink === null || userLink === undefined) {
    return `<section class="panel" id="detail-user"><h3>User</h3><p class="empty">Not resolved</p>${button}</section>`;
  }
  const users = Array.isArray(userLink.users) ? userLink.users : [];
  return [
    '<section class="panel" id="detail-user"><h3>User</h3>',
    field('status', cell(userLink.status)),
    field('resolvedAt', cell(userLink.resolvedAt)),
    users.length === 0
      ? ''
      : [
          '<table class="grid users">',
          '<thead><tr><th>displayName</th><th>userPrincipalName</th></tr></thead>',
          `<tbody>${users.map(userRow).join('')}</tbody>`,
          '</table>',
        ].join(''),
    button,
    '</section>',
  ].join('');
}

/** The device detail screen. */
export function render(state = {}) {
  const profile = state.profile ?? {};
  const inventory = state.inventory ?? null;
  const posture = state.posture ?? null;
  const commands = Array.isArray(state.commands) ? state.commands : [];
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

  return [
    `<section class="screen" id="screen-device-detail" data-device-id="${escapeHtml(profile.deviceId ?? state.deviceId)}">`,
    `<h2>${cell(profile.hostname ?? profile.deviceId ?? state.deviceId)}</h2>`,
    profileSection,
    userSection(state.userLink, profile.deviceId ?? state.deviceId),
    inventorySection,
    postureSection,
    commandsSection,
    '</section>',
  ].join('');
}

export const renderDeviceDetail = render;
