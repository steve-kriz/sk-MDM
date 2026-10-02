/**
 * The public landing page: fills in the install strings from the page origin.
 *
 * Served as `/assets/public/landing.js` (external, because the content
 * security policy forbids inline script). It never signs in, never fetches the
 * console configuration and never contacts Entra.
 *
 * The strings are built by pure functions so they are tested under `node
 * --test` without a DOM; only the guarded block at the bottom touches the page.
 * The collection URL follows the same rule as the console's settings screen:
 * the origin followed by `/`.
 */

/** The macOS install command: the pkg has the URL and token baked in, so it takes no parameters. */
export const MACOS_INSTALL_COMMAND = 'sudo installer -pkg <downloaded .pkg> -target /';

/** The collection URL an agent reports to: the page origin followed by `/`. */
export function collectionUrlFor(origin) {
  return `${origin}/`;
}

/** The silent Windows install command, carrying the collection URL as the COLLECTIONURL property. */
export function windowsInstallCommand(collectionUrl) {
  return `msiexec /i <downloaded .msi> /qn COLLECTIONURL=${collectionUrl} ENROLLTOKEN=<enrollment token>`;
}

/** Set an element's text, if the page has it. */
function setText(id, text) {
  const element = document.getElementById(id);
  if (element !== null) {
    element.textContent = text;
  }
}

if (typeof document !== 'undefined') {
  const collectionUrl = collectionUrlFor(window.location.origin);
  setText('collection-url', collectionUrl);
  setText('windows-install-command', windowsInstallCommand(collectionUrl));
}
