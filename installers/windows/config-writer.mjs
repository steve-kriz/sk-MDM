/**
 * Renders the agent config file the Windows installer writes to
 * C:\ProgramData\OfficeHQ\MDM\config.json.
 *
 * The key set and the refusal message are the ones agent/internal/config
 * defines: Load reads exactly collectionUrl, enrollmentToken,
 * checkInIntervalSeconds and logLevel, and refuses a collection URL that is
 * missing, unparseable or not https with "collection url must be an https url".
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

/**
 * Throws when `raw` is not a collection URL the agent may send collections to:
 * the enrollment token and the device secret travel over it, so nothing but
 * https with a host is accepted.
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
 * The config file contents for a collection URL and an enrollment token, as a
 * JSON string ending in a newline.
 */
export function renderConfig({ collectionUrl, enrollToken } = {}) {
  validateCollectionUrl(collectionUrl);

  const config = {
    collectionUrl,
    enrollmentToken: enrollToken ?? '',
    checkInIntervalSeconds: CHECK_IN_INTERVAL_SECONDS,
    logLevel: LOG_LEVEL,
  };

  return `${JSON.stringify(config, null, 2)}\n`;
}
