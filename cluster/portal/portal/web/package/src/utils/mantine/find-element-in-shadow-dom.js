const getShadowRoot = (element) => {
  try {
    return element.shadowRoot;
  } catch {
    return null;
  }
};

export const findElementBySelector = (selector, root = document) => {
  const element = root.querySelector(selector);
  if (element || root === document) return element;

  for (const host of root.querySelectorAll("*")) {
    const shadowRoot = getShadowRoot(host);
    if (!shadowRoot) continue;
    const found = findElementBySelector(selector, shadowRoot);
    if (found) return found;
  }
  return null;
};

export const findElementsBySelector = (selector, root = document) => {
  const elements = Array.from(root.querySelectorAll(selector));
  if (root === document) return elements;

  for (const host of root.querySelectorAll("*")) {
    const shadowRoot = getShadowRoot(host);
    if (shadowRoot)
      elements.push(...findElementsBySelector(selector, shadowRoot));
  }
  return elements;
};

export const getRootElement = (target) => {
  if (!target) return document;
  const root = target.getRootNode();
  return root instanceof ShadowRoot || root instanceof Document
    ? root
    : document;
};
