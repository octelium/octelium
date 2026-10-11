/// <reference types="vite-plugin-svgr/client" />

import Logo from "@/assets/l03.svg?react";
import {
  ActionIcon,
  Popover,
  SegmentedControl,
  useMantineColorScheme,
  type MantineColorScheme,
} from "@mantine/core";
import { useDisclosure, useReducedMotion, useTimeout } from "@mantine/hooks";
import { LuMonitor, LuMoon, LuSun } from "react-icons/lu";

const THEME_OPTIONS = [
  { value: "light", label: "Light", Icon: LuSun },
  { value: "dark", label: "Dark", Icon: LuMoon },
  { value: "auto", label: "System", Icon: LuMonitor },
] as const;

const TopBar = () => {
  const { colorScheme, setColorScheme, clearColorScheme } =
    useMantineColorScheme();
  const reduceMotion = useReducedMotion();
  const [opened, { open, close }] = useDisclosure(false);
  const { start: scheduleClose, clear: cancelClose } = useTimeout(close, 120);
  const selected = THEME_OPTIONS.find(({ value }) => value === colorScheme)!;
  const SchemeIcon = selected.Icon;

  return (
    <nav
      aria-label="Primary"
      className="w-full min-h-[60px] flex items-center justify-between gap-2 px-4 pt-[env(safe-area-inset-top)]"
    >
      <a
        aria-label="Octelium home"
        className="flex-none flex items-center justify-center"
        href="https://octelium.com"
        target="_blank"
      >
        <Logo
          aria-hidden="true"
          focusable="false"
          className="w-28 h-auto dark:invert sm:w-40"
        />
      </a>
      <div
        className="relative shrink-0"
        onPointerEnter={(event) => {
          if (event.pointerType === "mouse") {
            cancelClose();
            open();
          }
        }}
        onPointerLeave={(event) => {
          if (
            event.pointerType === "mouse" &&
            !event.currentTarget.contains(document.activeElement)
          ) {
            scheduleClose();
          }
        }}
        onBlur={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget)) {
            close();
          }
        }}
      >
        <Popover
          opened={opened}
          onChange={(value) => value ? open() : close()}
          position="left"
          offset={4}
          withinPortal={false}
          returnFocus
          transitionProps={{ transition: "fade", duration: reduceMotion ? 0 : 120 }}
          styles={{
            dropdown: {
              padding: 0,
              border: 0,
              background: "transparent",
              boxShadow: "none",
            },
          }}
        >
          <Popover.Target>
            <ActionIcon
              aria-label={`Appearance: ${selected.label}. Change appearance`}
              title="Change appearance"
              variant="subtle"
              radius="xl"
              size={32}
              className="after:absolute after:-inset-1.5 sm:after:inset-0 !text-fg-subtle hover:!text-fg"
              onClick={open}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  cancelClose();
                  close();
                }
              }}
            >
              <SchemeIcon size={13} aria-hidden="true" />
            </ActionIcon>
          </Popover.Target>
          <Popover.Dropdown>
            <SegmentedControl<MantineColorScheme>
              aria-label="Appearance"
              radius="xl"
              value={colorScheme}
              onChange={(value) => {
                if (value === "auto") {
                  clearColorScheme();
                } else {
                  setColorScheme(value);
                }
              }}
              onClick={(event) => {
                if ((event.target as HTMLElement).closest("label")) {
                  cancelClose();
                  close();
                }
              }}
              withItemsBorders={false}
              transitionDuration={reduceMotion ? 0 : 120}
              classNames={{
                label: "!h-10 !w-10 sm:!h-7 sm:!w-7 !text-fg-subtle hover:!text-fg data-[active]:!text-fg",
              }}
              styles={{
                root: {
                  background: "var(--portal-surface)",
                  border: "1px solid var(--portal-line)",
                  padding: 3,
                },
                label: {
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  padding: 0,
                },
                indicator: {
                  background: "var(--portal-surface-strong)",
                  boxShadow: "none",
                },
              }}
              data={THEME_OPTIONS.map(({ value, label, Icon }) => ({
                value,
                label: (
                  <span className="flex items-center justify-center" title={`${label} appearance`}>
                    <Icon size={13} aria-hidden="true" />
                    <span className="sr-only">{label}</span>
                  </span>
                ),
              }))}
            />
          </Popover.Dropdown>
        </Popover>
      </div>
    </nav>
  );
};

export default TopBar;
