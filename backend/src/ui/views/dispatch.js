/**
 * Sending a command to one device.
 *
 *   render({deviceId, hostname, type, payload, typedHostname})
 *   requestFor(state) -> {method, path, body} | null
 *
 * The screen refuses before the API does. `restart` and `run_script` can take a
 * machine away from whoever is sitting at it, so they are gated behind typing
 * the hostname exactly: until `typedHostname` equals `hostname` the send action
 * is disabled and `requestFor` produces nothing at all -- there is no body to
 * send by accident. Once they match, the body carries `confirm: true`, which is
 * what `POST /admin/api/v1/devices/{deviceId}/commands` requires before it will
 * queue a destructive command (it answers 409 `confirmation_required`
 * otherwise).
 *
 * The payload rules mirror the same route's, so a missing interpreter is named
 * here, in the field, rather than coming back as a 400.
 */
import { attributes, escapeHtml, join } from '../public/html.js';

/** The command types the API accepts; nothing else is offered. */
export const COMMAND_TYPES = ['run_script', 'restart', 'lock', 'install_package', 'uninstall_package', 'collect_logs'];

/** The types that may not be sent without typing the hostname. */
export const CONFIRM_REQUIRED_TYPES = ['restart', 'run_script'];

/** The interpreters a `run_script` payload may name. */
export const SCRIPT_INTERPRETERS = ['powershell', 'zsh'];

/** True when a value is a string with something in it. */
function filled(value) {
  return typeof value === 'string' && value.length > 0;
}

/** The payload fields this type needs but the state does not carry, in report order. */
export function fieldErrors(state = {}) {
  const payload = state.payload ?? {};
  const errors = [];
  if (state.type === 'run_script') {
    if (!SCRIPT_INTERPRETERS.includes(payload.interpreter)) {
      errors.push('payload.interpreter');
    }
    if (!filled(payload.script)) {
      errors.push('payload.script');
    }
  }
  if (state.type === 'install_package' || state.type === 'uninstall_package') {
    if (!filled(payload.packageId)) {
      errors.push('payload.packageId');
    }
  }
  return errors;
}

/** True when this type may not be sent until the hostname has been typed back. */
export function confirmationRequired(state = {}) {
  return CONFIRM_REQUIRED_TYPES.includes(state.type);
}

/** True when the operator has typed the device's own hostname, exactly. */
export function confirmed(state = {}) {
  return filled(state.hostname) && state.typedHostname === state.hostname;
}

/** True when the send action is live: a known type, a complete payload, and confirmation. */
export function sendEnabled(state = {}) {
  if (!COMMAND_TYPES.includes(state.type) || fieldErrors(state).length > 0) {
    return false;
  }
  return !confirmationRequired(state) || confirmed(state);
}

/** The body to POST, or `null` while the screen is refusing to send. */
export function requestBody(state = {}) {
  if (!sendEnabled(state)) {
    return null;
  }
  const body = { type: state.type, payload: state.payload ?? {} };
  return confirmationRequired(state) ? { ...body, confirm: true } : body;
}

/** The whole request, or `null` while the screen is refusing to send. */
export function requestFor(state = {}) {
  const body = requestBody(state);
  if (body === null) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/devices/${state.deviceId}/commands`, body };
}

/** The `<option>` list of command types. */
function typeOptions(selected) {
  return COMMAND_TYPES.map(
    (type) => `<option value="${type}"${type === selected ? ' selected' : ''}>${type}</option>`,
  ).join('');
}

/** One named field error, as the screen shows it. */
function errorFor(errors, field) {
  return errors.includes(field) ? `<p class="field-error" data-field="${field}">${field} is required</p>` : '';
}

/** The payload fields this type asks for. */
function payloadFields(state, errors) {
  const payload = state.payload ?? {};
  if (state.type === 'run_script') {
    const options = SCRIPT_INTERPRETERS.map(
      (name) => `<option value="${name}"${payload.interpreter === name ? ' selected' : ''}>${name}</option>`,
    ).join('');
    return join([
      `<label for="payload-interpreter">payload.interpreter</label>`,
      `<select id="payload-interpreter" name="payload.interpreter"><option value=""></option>${options}</select>`,
      errorFor(errors, 'payload.interpreter'),
      `<label for="payload-script">payload.script</label>`,
      `<textarea id="payload-script" name="payload.script">${escapeHtml(payload.script)}</textarea>`,
      errorFor(errors, 'payload.script'),
    ]);
  }
  if (state.type === 'install_package' || state.type === 'uninstall_package') {
    return join([
      `<label for="payload-package">payload.packageId</label>`,
      `<input id="payload-package" name="payload.packageId" value="${escapeHtml(payload.packageId)}">`,
      errorFor(errors, 'payload.packageId'),
    ]);
  }
  return '';
}

/** The command dispatch screen. */
export function render(state = {}) {
  const errors = fieldErrors(state);
  const enabled = sendEnabled(state);

  const confirmation = confirmationRequired(state)
    ? join([
        '<div class="confirm">',
        `<label for="confirm-hostname">Type <strong>${escapeHtml(state.hostname)}</strong> to confirm</label>`,
        `<input id="confirm-hostname" name="typedHostname" value="${escapeHtml(state.typedHostname)}">`,
        confirmed(state)
          ? ''
          : `<p class="field-error" data-field="typedHostname">The hostname must match ${escapeHtml(state.hostname)}</p>`,
        '</div>',
      ])
    : '';

  return join([
    `<section class="screen" id="screen-dispatch" data-device-id="${escapeHtml(state.deviceId)}">`,
    `<h2>Send a command to ${escapeHtml(state.hostname)}</h2>`,
    '<form class="dispatch">',
    '<label for="command-type">type</label>',
    `<select id="command-type" name="type">${typeOptions(state.type)}</select>`,
    payloadFields(state, errors),
    confirmation,
    `<button type="submit" class="send"${attributes({ disabled: !enabled })}>Send</button>`,
    '</form>',
    '</section>',
  ]);
}

export const renderDispatch = render;
