import { createSignal } from "solid-js";

export type Theme = "light" | "dark";

const STORAGE_KEY = "lwauth:theme";

function initialTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  // jsdom (and some older embedded webviews) don't implement matchMedia —
  // fall back to light rather than throwing on module load.
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

function applyTheme(t: Theme) {
  // index.html applies the .dark class synchronously pre-paint (avoids a
  // flash of the wrong theme on load); this keeps it in sync on every
  // change after that and persists the operator's explicit choice.
  document.documentElement.classList.toggle("dark", t === "dark");
  localStorage.setItem(STORAGE_KEY, t);
}

const [theme, setThemeSignal] = createSignal<Theme>(initialTheme());
export { theme };

export function toggleTheme() {
  setThemeSignal((t) => {
    const next = t === "dark" ? "light" : "dark";
    applyTheme(next);
    return next;
  });
}
