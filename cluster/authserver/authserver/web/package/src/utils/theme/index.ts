import {
  Button,
  createTheme,
  localStorageColorSchemeManager,
  MultiSelect,
  NumberInput,
  PinInput,
  Select,
  Switch,
  Textarea,
  TextInput,
  Tooltip,
  virtualColor,
  type CSSVariablesResolver,
} from "@mantine/core";

export const colorSchemeManager = localStorageColorSchemeManager({
  key: "octelium-auth-color-scheme",
});

export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: {},
  dark: {
    "--mantine-color-black": "var(--portal-surface)",
    "--mantine-color-dark-0": "var(--portal-fg)",
    "--mantine-color-dark-1": "var(--portal-fg-muted)",
    "--mantine-color-dark-2": "var(--portal-fg-subtle)",
    "--mantine-color-dark-4": "var(--portal-line)",
    "--mantine-color-dark-5": "var(--portal-surface-strong)",
    "--mantine-color-dark-6": "var(--portal-surface-strong)",
    "--mantine-color-dark-7": "var(--portal-surface)",
    "--mantine-color-dark-8": "var(--portal-canvas)",
    "--mantine-color-dark-9": "var(--portal-canvas)",
    "--mantine-color-default-color": "var(--portal-fg)",
    "--mantine-color-accent-filled": "var(--portal-accent)",
    "--mantine-color-accent-filled-hover": "var(--portal-accent-hover)",
    "--mantine-color-accent-outline": "var(--portal-accent)",
    "--mantine-color-accent-contrast": "var(--portal-accent-fg)",
    "--mantine-color-accent-light": "var(--portal-surface-strong)",
    "--mantine-color-accent-light-color": "var(--portal-fg)",
    "--mantine-primary-color-light": "var(--portal-surface-strong)",
    "--mantine-primary-color-light-color": "var(--portal-fg)",
  },
});

const theme = createTheme({
  fontFamily: "Ubuntu, sans-serif",

  colors: {
    accent: virtualColor({ name: "accent", light: "dark", dark: "gray" }),
  },
  primaryColor: "accent",
  autoContrast: true,
  defaultRadius: "md",
  // focusRing: "never",

  components: {
    Button: Button.extend({
      defaultProps: {
        variant: "filled",
        className: "font-bold shadow-md transition-all duration-500 rounded-md",
      },
    }),
    TextInput: TextInput.extend({
      classNames: {
        label: "font-bold",
        input:
          "font-bold focus:shadow-md transition-all duration-500 rounded-md focus:border-accent border-[2px]",
      },
    }),
    Textarea: Textarea.extend({
      classNames: {
        label: "font-bold",
        input:
          "font-semibold focus:shadow-md transition-all duration-500 rounded-md focus:border-accent border-[2px]",
      },
    }),
    NumberInput: NumberInput.extend({
      classNames: {
        label: "font-bold",
        input:
          "font-bold focus:shadow-md transition-all duration-500 rounded-md focus:border-accent border-[2px]",
      },
    }),
    PinInput: PinInput.extend({
      classNames: {
        input:
          "!font-bold !focus:shadow-md !transition-all !duration-500 rounded-md !focus:border-accent !border-[2px]",
      },
    }),
    Switch: Switch.extend({
      defaultProps: {
        // size: "md",
      },
      classNames: {
        label: "font-bold",
        input: "transition-all duration-500",
      },
    }),
    Select: Select.extend({
      defaultProps: {
        radius: "md",
        comboboxProps: {
          transitionProps: { transition: "pop", duration: 200 },
          shadow: "sm",
          radius: "md",
        },
      },
      classNames: {
        input: "border-[2px]",
        label: "font-bold",
        option: "transition-all duration-500 font-bold hover:bg-surface-strong",
      },
    }),
    MultiSelect: MultiSelect.extend({
      defaultProps: {
        radius: "md",
        comboboxProps: {
          transitionProps: { transition: "pop", duration: 200 },
          shadow: "sm",
          radius: "md",
        },
      },
      classNames: {
        input: "border-[2px]",
        label: "font-bold",
        option: "transition-all duration-500 font-bold hover:bg-surface-strong",
      },
    }),
    Tooltip: Tooltip.extend({
      defaultProps: {
        transitionProps: {
          transition: "fade",
          duration: 350,
        },
        classNames: {
          tooltip: "shadow-md font-bold text-xs rounded-sm",
        },
      },
    }),
  },
});

export default theme;
