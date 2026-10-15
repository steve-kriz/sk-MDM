/**
 * Renders the agent config file the Windows installer writes to
 * C:\ProgramData\OfficeHQ\MDM\config.json.
 *
 * The key set and the refusal message are the ones agent/internal/config
 * defines: Load reads collectionUrl, ownership, tenantId, clientId, the
 * optional legacy enrollmentToken, checkInIntervalSeconds and logLevel, and
 * refuses a collection URL that is missing, unparseable or not https with
 * "collection url must be an https url".
 *
 * installers/windows/write-config.js is the JScript twin of this module that
 * actually runs inside the MSI; installers/test/windows-config-writer.test.js
 * runs both and holds them to the same output.
 *
 * This module only renders text. It touches no files, so a refused URL cannot
 * leave a half-written config behind.
 */

/** The check-in interval the agent defaults to: fifteen minutes. */
export const CHECK_IN_INTERVAL_SECONDS = 900;

/** The level the agent logs at unless told otherwise. */
export const LOG_LEVEL = 'info';

/** The message a bad collection URL is refused with, from agent/internal/config. */
export const COLLECTION_URL_ERROR = 'collection url must be an https url';

/** The device types the installer offers; the first is the default. */
export const OWNERSHIPS = ['officehq', 'byoc'];

/** The message an unknown ownership is refused with. */
export const OWNERSHIP_ERROR = 'ownership must be officehq or byoc';

/**
 * Throws when `raw` is not a collection URL the agent may send collections to:
 * the user's token and the device secret travel over it, so nothing but https
 * with a host is accepted.
 */
export function validateCollectionUrl(raw) {
  if (typeof raw !== 'string' || raw === '') {
    throw new Error(COLLECTION_URL_ERROR);
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(COLLECTION_URL_ERROR);
  }

  if (parsed.protocol !== 'https:' || parsed.host === '') {
    throw new Error(COLLECTION_URL_ERROR);
  }
}

/**
 * The config file contents as a JSON string ending in a newline.
 *
 * `ownership` defaults to "officehq"; `tenantId` and `clientId` are written
 * when given (the agent fetches them from the backend otherwise); the legacy
 * `enrollToken` is written only when non-empty.
 */
export function renderConfig({ collectionUrl, ownership, tenantId, clientId, enrollToken } = {}) {
  validateCollectionUrl(collectionUrl);

  const resolvedOwnership = ownership === undefined || ownership === '' ? OWNERSHIPS[0] : ownership;
  if (!OWNERSHIPS.includes(resolvedOwnership)) {
    throw new Error(OWNERSHIP_ERROR);
  }

  const config = { collectionUrl, ownership: resolvedOwnership };
  if (tenantId) {
    config.tenantId = tenantId;
  }
  if (clientId) {
    config.clientId = clientId;
  }
  if (enrollToken) {
    config.enrollmentToken = enrollToken;
  }
  config.checkInIntervalSeconds = CHECK_IN_INTERVAL_SECONDS;
  config.logLevel = LOG_LEVEL;

  return `${JSON.stringify(config, null, 2)}\n`;
}
