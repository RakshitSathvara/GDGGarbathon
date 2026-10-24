/**
 * Minimal DOM helpers. Text is only ever assigned through textContent (never parsed as HTML),
 * which keeps model output and uploaded titles from becoming markup.
 */

/** @param {string} id */
export function byId(id) {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing #${id} in index.html`);
  return node;
}

/**
 * @param {string} tag
 * @param {{ className?: string, text?: string, lang?: string, attrs?: Record<string, string> }} [options]
 * @param {(Node | string)[]} [children]
 */
export function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.lang) node.lang = options.lang;
  for (const [name, value] of Object.entries(options.attrs ?? {})) node.setAttribute(name, value);
  node.append(...children);
  return node;
}

/** Skips re-rendering a section whose data signature has not changed since the last render. */
export function createRenderCache() {
  const signatures = new Map();
  return {
    /** @param {string} key @param {string} signature @param {() => void} render */
    renderOnChange(key, signature, render) {
      if (signatures.get(key) === signature) return;
      signatures.set(key, signature);
      render();
    },
  };
}
