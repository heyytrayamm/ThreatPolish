/** The console themes.
 *
 * `console` is the deep-space holographic HUD and `daylight` is the bright-room
 * variant of the same language. The choice lives in `data-theme` on `<html>`,
 * where `styles.css` reads it; this module only decides and stores it.
 */

export type Theme = "console" | "daylight";

const STORAGE_KEY = "tp-theme";

function isTheme(value: string | null): value is Theme {
  return value === "console" || value === "daylight";
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
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "daylight" : "console";
}

/** Apply a theme to the document and remember it. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Not remembering the choice is better than failing to apply it.
  }
}
