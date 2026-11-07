import {
  SegmentedControl,
  useMantineColorScheme,
  type MantineColorScheme,
} from "@mantine/core";
import { useReducedMotion } from "@mantine/hooks";
import { LuMonitor, LuMoon, LuSun } from "react-icons/lu";

const OPTIONS = [
  { value: "light", label: "Light", Icon: LuSun },
  { value: "dark", label: "Dark", Icon: LuMoon },
  { value: "auto", label: "System", Icon: LuMonitor },
] as const;

const AppearanceControl = () => {
  const { colorScheme, setColorScheme, clearColorScheme } =
    useMantineColorScheme();
  const reduceMotion = useReducedMotion();

  return (
    <SegmentedControl<MantineColorScheme>
      aria-label="Appearance"
      radius="xl"
      size="xs"
      value={colorScheme}
      onChange={(value) => {
        if (value === "auto") {
          clearColorScheme();
        } else {
          setColorScheme(value);
        }
      }}
      withItemsBorders={false}
      transitionDuration={reduceMotion ? 0 : 300}
      classNames={{
        label:
          "!flex !h-10 !w-10 !items-center !justify-center !p-0 !text-fg-subtle transition-colors duration-300 hover:!text-fg data-[active]:!text-fg sm:!h-7 sm:!w-8",
      }}
      styles={{
        root: {
          background: "var(--portal-surface)",
          border: "1px solid var(--portal-line)",
          padding: 2,
        },
        indicator: {
          background: "var(--portal-surface-strong)",
          boxShadow: "0 0 0 1px var(--portal-line)",
        },
      }}
      data={OPTIONS.map(({ value, label, Icon }) => ({
        value,
        label: (
          <span className="flex items-center justify-center" title={label}>
            <Icon size={14} aria-hidden="true" />
            <span className="sr-only">{label}</span>
          </span>
        ),
      }))}
    />
  );
};

export default AppearanceControl;
