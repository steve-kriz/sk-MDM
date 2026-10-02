/**
 * The HTML the views build, escaped.
 *
 *   escapeHtml('<script>')  -> '&lt;script&gt;'
 *   cell(null)              -> '&mdash;'
 *
 * Every view renders a string rather than touching the DOM, so every value a
 * view interpolates -- a hostname, a script body, an audit actor -- has to be
 * escaped here before it reaches that string. The rules are the conservative
 * ones: the five characters that can end an element, start one, or break out of
 * an attribute.
 *
 * This module is imported by the view modules as `../public/html.js`, which is
 * both where it sits on disk and where the Lambda serves it from
 * (`/assets/public/html.js`), so the same import works in `node --test` and in
 * the browser.
 */

const ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escape a value for use as element text or inside a double-quoted attribute. */
export function escapeHtml(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value).replace(/[&<>"']/g, (character) => ESCAPES[character]);
}

/** A table cell's text: an escaped value, or an em dash when there is none. */
export function cell(value) {
  if (value === null || value === undefined || value === '') {
    return '&mdash;';
  }
  return escapeHtml(value);
}

/** Join rendered fragments, dropping the empty ones. */
export function join(fragments, separator = '\n') {
  return fragments.filter((fragment) => fragment !== '' && fragment !== null && fragment !== undefined).join(separator);
}

/** `attributes({class: 'row', disabled: true})` -> ` class="row" disabled`. */
export function attributes(pairs) {
  const parts = [];
  for (const [name, value] of Object.entries(pairs)) {
    if (value === false || value === null || value === undefined) {
      continue;
    }
    parts.push(value === true ? ` ${name}` : ` ${name}="${escapeHtml(value)}"`);
  }
  return parts.join('');
}
