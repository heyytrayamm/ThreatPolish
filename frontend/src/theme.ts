/** The console themes.
 *
 * `console` is the deep-space holographic HUD and `daylight` is the bright-room
 * variant of the same language. The choice lives in `data-theme` on `<html>`,
 * where `styles.css` reads it; this module only decides and stores it.
 *
 * A switch made in the ribbon is remembered and then outranks the host for
 * good. Until one is made the host preference wins, and it keeps winning while
 * the page is open: `watchHostTheme` reports a change as the operating system
 * flips between light and dark, so a console left open overnight follows the
 * room rather than the state it was loaded in.
 */

export type Theme = "console" | "daylight";

const STORAGE_KEY = "tp-theme";
const LIGHT_QUERY = "(prefers-color-scheme: light)";

function isTheme(value: string | null): value is Theme {
  return value === "console" || value === "daylight";
}

/** The host preference, or null where the browser cannot answer the question.
 *
 * `matchMedia` is missing in environments that are not browsers and in very
 * old engines; it is absent there, not an error, so the caller falls back to
 * the console rather than failing to render at all.
 */
function hostQuery(): MediaQueryList | null {
  try {
    return typeof window.matchMedia === "function" ? window.matchMedia(LIGHT_QUERY) : null;
  } catch {
    // Some embedders expose `matchMedia` but refuse to run it.
    return null;
  }
}

function hostTheme(): Theme {
  return hostQuery()?.matches ? "daylight" : "console";
}

/** The stored choice, else whatever the host reports it prefers. */
export function readTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (isTheme(stored)) return stored;
  } catch {
    // Storage can be unavailable (private mode, blocked cookies); the host
    // preference is still a fine answer.
  }
  return hostTheme();
}

/** Whether a switch has been made in this browser, which the host cannot override. */
export function hasStoredTheme(): boolean {
  try {
    return isTheme(window.localStorage.getItem(STORAGE_KEY));
  } catch {
    return false;
  }
}

/** Apply a theme to the document. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
}

/** Apply a theme and remember it as this browser's choice. */
export function rememberTheme(theme: Theme): void {
  applyTheme(theme);
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Not remembering the choice is better than failing to apply it.
  }
}

/** Call `listener` whenever the host reports a different colour scheme.
 *
 * Returns the unsubscribe function.  A host preference that no longer matters
 * (a switch has been stored) is filtered here rather than by the caller.
 */
export function watchHostTheme(listener: (theme: Theme) => void): () => void {
  const query = hostQuery();
  if (!query) return () => {};
  const onChange = () => {
    if (!hasStoredTheme()) listener(query.matches ? "daylight" : "console");
  };
  // WebKit shipped `addEventListener` on MediaQueryList after the deprecated
  // `addListener`, and the older form is still what some embedded browsers
  // expose.  A missing listener must not take the workspace down with it.
  if (typeof query.addEventListener === "function") {
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }
  query.addListener(onChange);
  return () => query.removeListener(onChange);
}
