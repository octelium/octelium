import {
  Button,
  createTheme,
  Drawer,
  Input,
  Menu,
  Modal,
  Pagination,
  SegmentedControl,
  Select,
  TextInput,
  Tooltip,
  virtualColor,
  type MantineColorsTuple,
  type MantineTransition,
} from "@mantine/core";

const FONT =
  'Ubuntu, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

const SIZE_MICRO = "0.6875rem";
const SIZE_META = "0.75rem";
const SIZE_BODY = "0.8125rem";

const labelStyles = {
  label: {
    fontSize: SIZE_META,
    fontWeight: 600,
    fontFamily: FONT,
    color: "var(--color-slate-700)",
    marginBottom: "4px",
  },
  description: {
    fontSize: SIZE_META,
    fontWeight: 400,
    fontFamily: FONT,
    lineHeight: 1.45,
    color: "var(--color-slate-500)",
    marginBottom: "6px",
  },
  error: {
    fontSize: SIZE_META,
    fontWeight: 500,
    fontFamily: FONT,
    color: "var(--color-red-600)",
  },
};

const inputStyles = {
  input: {
    fontSize: SIZE_BODY,
    fontWeight: 400,
    fontFamily: FONT,
    backgroundColor: "var(--color-white)",
    border: "1px solid var(--color-slate-200)",
    borderRadius: "8px",
    color: "var(--color-slate-900)",
    boxShadow: "none",
    minHeight: "38px",
    transition: "border-color 150ms, box-shadow 150ms",
  },
};

const optionStyles = {
  option: {
    fontSize: SIZE_BODY,
    fontWeight: 400,
    fontFamily: FONT,
    borderRadius: "7px",
    minHeight: "34px",
    transition: "background-color 150ms, color 150ms",
  },
};

const comboboxDefaultProps = {
  radius: "md" as const,
  comboboxProps: {
    transitionProps: { transition: "pop" as MantineTransition, duration: 150 },
    shadow: "md",
    radius: "lg" as const,
  },
};

const INK_LIGHT: MantineColorsTuple = [
  "#c9c9c9",
  "#b8b8b8",
  "#828282",
  "#696969",
  "#424242",
  "#3b3b3b",
  "#2e2e2e",
  "#242424",
  "#1f1f1f",
  "#141414",
];

const INK_DARK: MantineColorsTuple = [
  "#99a6b8",
  "#a6b2c3",
  "#b4bfce",
  "#c2cbd9",
  "#cdd5e0",
  "#d8dfe8",
  "#dfe5ed",
  "#e5eaf1",
  "#eaeff5",
  "#d4dbe6",
];

export const OVERLAY_Z_INDEX = 220;

const theme = createTheme({
  fontFamily: FONT,
  fontFamilyMonospace:
    "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  primaryColor: "ink",
  autoContrast: true,

  colors: {
    inkLight: INK_LIGHT,
    inkDark: INK_DARK,
    ink: virtualColor({ name: "ink", light: "inkLight", dark: "inkDark" }),
  },
  defaultRadius: "md",
  cursorType: "pointer",

  components: {
    Button: Button.extend({
      defaultProps: { variant: "filled" },
      styles: {
        root: {
          fontFamily: FONT,
          fontWeight: 600,
          fontSize: SIZE_BODY,
          borderRadius: "8px",
          transition:
            "background-color 150ms, border-color 150ms, color 150ms, opacity 150ms",
          boxShadow: "none",
        },
        label: { fontFamily: FONT, fontWeight: 600 },
      },
    }),

    Modal: Modal.extend({ defaultProps: { zIndex: OVERLAY_Z_INDEX } }),

    Drawer: Drawer.extend({ defaultProps: { zIndex: OVERLAY_Z_INDEX } }),

    Input: Input.extend({ styles: { ...labelStyles, ...inputStyles } }),

    TextInput: TextInput.extend({ styles: { ...labelStyles, ...inputStyles } }),

    Select: Select.extend({
      defaultProps: comboboxDefaultProps,
      styles: { ...labelStyles, ...inputStyles, ...optionStyles },
    }),

    SegmentedControl: SegmentedControl.extend({
      styles: {
        root: {
          backgroundColor: "var(--color-slate-100)",
          border: "1px solid var(--color-slate-200)",
          borderRadius: "10px",
          padding: "3px",
        },
        label: {
          fontSize: SIZE_BODY,
          fontWeight: 600,
          color: "var(--color-slate-500)",
          transition: "color 150ms",
        },
        indicator: {
          backgroundColor: "var(--color-white)",
          borderRadius: "7px",
          boxShadow: "var(--shadow-card)",
          transition: "transform 150ms ease, width 150ms ease",
        },
      },
    }),

    Pagination: Pagination.extend({
      styles: {
        control: {
          fontFamily: FONT,
          fontWeight: 600,
          fontSize: SIZE_BODY,
          border: "1px solid var(--color-slate-200)",
          backgroundColor: "var(--color-white)",
          color: "var(--color-slate-600)",
          boxShadow: "none",
          transition: "background-color 150ms, border-color 150ms, color 150ms",
        },
      },
    }),

    Menu: Menu.extend({
      defaultProps: {
        shadow: "md",
        radius: "lg",
        transitionProps: {
          transition: "pop" as MantineTransition,
          duration: 150,
        },
      },
      styles: {
        dropdown: {
          border: "1px solid var(--color-slate-200)",
          boxShadow: "var(--shadow-overlay)",
          padding: "6px",
        },
        item: {
          borderRadius: "7px",
          fontFamily: FONT,
          fontSize: SIZE_BODY,
          fontWeight: 500,
          minHeight: "34px",
          transition: "background-color 150ms, color 150ms",
        },
        label: {
          color: "var(--color-slate-500)",
          fontFamily: FONT,
          fontSize: SIZE_MICRO,
          fontWeight: 600,
          letterSpacing: "0.05em",
          textTransform: "uppercase",
        },
        divider: { borderColor: "var(--color-slate-200)" },
      },
    }),

    Tooltip: Tooltip.extend({
      defaultProps: {
        transitionProps: {
          transition: "fade" as MantineTransition,
          duration: 150,
        },
      },
      styles: {
        tooltip: {
          fontFamily: FONT,
          fontWeight: 400,
          fontSize: SIZE_META,
          backgroundColor: "var(--color-slate-900)",
          color: "var(--color-slate-50)",
          border: "1px solid var(--color-slate-800)",
          borderRadius: "8px",
          boxShadow: "var(--shadow-raised)",
          padding: "5px 10px",
        },
      },
    }),
  },
});

export default theme;
