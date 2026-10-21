import "@testing-library/jest-dom/vitest";

window.getComputedStyle = () =>
  ({
    getPropertyValue: () => "",
  }) as unknown as CSSStyleDeclaration;

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});
