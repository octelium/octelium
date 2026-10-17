import { localStorageColorSchemeManager } from "@mantine/core";

import type { MantineColorScheme } from "@mantine/core";

export const COLOR_SCHEME_STORAGE_KEY = "octelium-portal-color-scheme";

export const DEFAULT_COLOR_SCHEME: MantineColorScheme = "auto";

export const colorSchemeManager = localStorageColorSchemeManager({
  key: COLOR_SCHEME_STORAGE_KEY,
});

export const COLOR_SCHEMES: { value: MantineColorScheme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "auto", label: "System" },
];
