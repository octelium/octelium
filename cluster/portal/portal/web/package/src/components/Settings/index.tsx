import {
  Popover,
  SegmentedControl,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Cog, Moon, Sun } from "lucide-react";

const OptionLabel = (props: { icon: React.ReactNode; label: string }) => (
  <span className="flex items-center justify-center gap-1.5 font-bold">
    {props.icon}
    {props.label}
  </span>
);

const Settings = () => {
  const [opened, { toggle, close }] = useDisclosure(false);
  const { colorScheme, setColorScheme } = useMantineColorScheme();

  return (
    <Popover
      opened={opened}
      onDismiss={close}
      position="bottom-end"
      width={244}
      shadow="md"
      radius="md"
      transitionProps={{ transition: "pop", duration: 200 }}
    >
      <Popover.Target>
        <button
          type="button"
          aria-label="Settings"
          aria-expanded={opened}
          title="Settings"
          className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg text-fg-subtle transition-colors duration-300 hover:bg-surface-active hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          onClick={toggle}
        >
          <Cog size={18} aria-hidden />
        </button>
      </Popover.Target>

      <Popover.Dropdown>
        <div className="text-[11px] font-bold tracking-wide text-fg-faint uppercase">
          Appearance
        </div>

        <SegmentedControl
          aria-label="Appearance"
          className="mt-2"
          fullWidth
          size="xs"
          radius="md"
          value={colorScheme === "dark" ? "dark" : "light"}
          onChange={(value) =>
            setColorScheme(value === "dark" ? "dark" : "light")
          }
          data={[
            {
              value: "light",
              label: (
                <OptionLabel
                  icon={<Sun size={14} aria-hidden />}
                  label="Light"
                />
              ),
            },
            {
              value: "dark",
              label: (
                <OptionLabel
                  icon={<Moon size={14} aria-hidden />}
                  label="Dark"
                />
              ),
            },
          ]}
        />

        <p className="mt-2 mb-0 text-xs font-medium text-fg-subtle">
          Applied to this browser only.
        </p>
      </Popover.Dropdown>
    </Popover>
  );
};

export default Settings;
