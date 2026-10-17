import type { CSSVariablesResolver } from "@mantine/core";

const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: {},
  dark: {
    "--mantine-color-black": "var(--color-white)",

    "--mantine-color-dark-0": "var(--color-slate-700)",
    "--mantine-color-dark-1": "var(--color-slate-600)",
    "--mantine-color-dark-2": "var(--color-slate-500)",
    "--mantine-color-dark-3": "var(--color-slate-400)",
    "--mantine-color-dark-4": "var(--color-slate-200)",
    "--mantine-color-dark-5": "var(--color-slate-100)",
    "--mantine-color-dark-6": "var(--color-slate-50)",
    "--mantine-color-dark-7": "var(--color-white)",
    "--mantine-color-dark-8": "var(--color-canvas)",
    "--mantine-color-dark-9": "var(--color-canvas)",

    "--mantine-color-ink-light": "var(--color-slate-100)",
    "--mantine-color-ink-light-hover": "var(--color-slate-200)",
    "--mantine-color-ink-light-color": "var(--color-slate-800)",
    "--mantine-color-ink-outline": "var(--color-slate-300)",

    "--mantine-primary-color-light": "var(--color-slate-100)",
    "--mantine-primary-color-light-hover": "var(--color-slate-200)",
    "--mantine-primary-color-light-color": "var(--color-slate-800)",
  },
});

export default cssVariablesResolver;
