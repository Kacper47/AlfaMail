// Small DOM helpers. Everything user-controlled is inserted with textContent / text
// nodes, never as HTML, so message content cannot inject markup or script.

export const $ = (id) => document.getElementById(id);

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

export function show(node, message) {
  node.textContent = message;
  node.hidden = !message;
}

export const USERNAME_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;

export function normaliseUsername(raw) {
  return raw.trim().toLowerCase();
}
