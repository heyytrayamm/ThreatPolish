/**
 * Copy text with the Clipboard API, falling back to a selected temporary field.
 *
 * `navigator.clipboard` is unavailable outside a secure context and can reject
 * when the document is not focused or the permission is denied. The fallback
 * still runs inside the click handler, so browsers that support `execCommand`
 * copy the same text.
 */
export async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Fall through to the selection-based copy.
    }
  }

  const area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "0";
  area.style.left = "0";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  area.setSelectionRange(0, value.length);

  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  } finally {
    area.remove();
  }

  if (!copied) throw new Error("the browser refused the copy request");
}
