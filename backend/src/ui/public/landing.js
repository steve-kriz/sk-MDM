/**
 * The public landing page: fills in the install strings from the page origin
 * and the published version next to each download link.
 *
 * Served as `/assets/public/landing.js` (external, because the content
 * security policy forbids inline script). It never signs in, never fetches the
 * console configuration and never contacts Entra; its one request is the
 * public `GET /api/v1/downloads` on its own origin.
 *
 * The strings are built by pure functions so they are tested under `node
 * --test` without a DOM; only the guarded block at the bottom touches the page.
 * The collection URL follows the same rule as the console's settings screen:
 * the origin followed by `/`.
 */

/** The macOS install command: the pkg has its values baked in, so it takes no parameters. */
export const MACOS_INSTALL_COMMAND = 'sudo installer -pkg <downloaded .pkg> -target /';

/** Where the published installer versions are read from. */
export const DOWNLOADS_PATH = '/api/v1/downloads';

/** The download platforms, as the `version-<platform>` element ids name them. */
const PLATFORMS = ['windows-x64', 'windows-arm64', 'macos-amd64', 'macos-arm64'];

/** The collection URL an agent reports to: the page origin followed by `/`. */
export function collectionUrlFor(origin) {
  return `${origin}/`;
}

/**
 * The silent Windows install command. The MSI already carries the collection
 * URL; naming it and the device type makes a scripted install explicit.
 */
export function windowsInstallCommand(collectionUrl) {
  return `msiexec /i <downloaded .msi> /qn COLLECTIONURL=${collectionUrl} OWNERSHIP=officehq`;
}

/** What is shown next to a download link for a published version, or for none. */
export function versionLabel(version) {
  return typeof version === 'string' && version.length > 0 ? `Version ${version}` : 'Not yet published';
}

/** Set an element's text, if the page has it. */
function setText(id, text) {
  const element = document.getElementById(id);
  if (element !== null) {
    element.textContent = text;
  }
}

/** Fill every version slot; a failed read leaves them blank rather than guessing. */
async function showVersions() {
  try {
    const response = await fetch(DOWNLOADS_PATH, { headers: { accept: 'application/json' } });
    if (!response.ok) {
      return;
    }
    const { versions } = await response.json();
    for (const platform of PLATFORMS) {
      setText(`version-${platform}`, versionLabel(versions?.[platform]));
    }
  } catch {
    // The links still work without a version beside them.
  }
}

if (typeof document !== 'undefined') {
  const collectionUrl = collectionUrlFor(window.location.origin);
  setText('collection-url', collectionUrl);
  setText('windows-install-command', windowsInstallCommand(collectionUrl));
  void showVersions();
}
