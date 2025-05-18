import {
  createTheme,
  MantineProvider,
  Button,
  TextInput,
  NumberInput,
  Switch,
  Select,
  MultiSelect,
  Textarea,
  Tooltip,
} from "@mantine/core";
// import { fontFamily } from ".";

const theme = createTheme({
  // fontFamily: fontFamily,
  fontFamily: [
    "-apple-system",
    "BlinkMacSystemFont",
    "Ubuntu",
    '"Segoe UI"',
    "Roboto",
    '"Helvetica Neue"',
    "Arial",
    "sans-serif",
    '"Apple Color Emoji"',
    '"Segoe UI Emoji"',
    '"Segoe UI Symbol"',
  ].join(","),

  primaryColor: "dark",
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
          "font-bold focus:shadow-md transition-all duration-500 rounded-md focus:border-gray-900 border-[2px]",
      },
    }),
    Textarea: Textarea.extend({
      classNames: {
        label: "font-bold",
        input:
          "font-semibold focus:shadow-md transition-all duration-500 rounded-md focus:border-gray-900 border-[2px]",
      },
    }),
    NumberInput: NumberInput.extend({
      classNames: {
        label: "font-bold",
        input:
          "font-bold focus:shadow-md transition-all duration-500 rounded-md focus:border-gray-900 border-[2px]",
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
        option: "transition-all duration-500 font-bold hover:bg-zinc-200",
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
        option: "transition-all duration-500 font-bold hover:bg-zinc-200",
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