/// <reference types="vite-plugin-svgr/client" />

import Logo from "@/assets/l03.svg?react";
import { ActionIcon, Menu, useMantineColorScheme } from "@mantine/core";
import { useReducedMotion } from "@mantine/hooks";
import { LuCheck, LuMonitor, LuMoon, LuSun } from "react-icons/lu";

const TopBar = () => {
  const { colorScheme, setColorScheme, clearColorScheme } =
    useMantineColorScheme();
  const SchemeIcon =
    colorScheme === "dark" ? LuMoon : colorScheme === "light" ? LuSun : LuMonitor;
  const reduceMotion = useReducedMotion();

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
      <Menu
        position="bottom-end"
        shadow="md"
        width={160}
        transitionProps={{
          transition: "pop-top-right",
          duration: reduceMotion ? 0 : 160,
          timingFunction: "cubic-bezier(0.2, 0.8, 0.2, 1)",
        }}
      >
        <Menu.Target>
          <ActionIcon
            aria-label={`Appearance: ${colorScheme === "auto" ? "System" : colorScheme}. Change appearance`}
            title="Change appearance"
            variant="subtle"
            size="lg"
            className="text-fg"
          >
            <SchemeIcon size={20} aria-hidden="true" />
          </ActionIcon>
        </Menu.Target>
        <Menu.Dropdown>
          <Menu.Label>Appearance</Menu.Label>
          <Menu.Item
            leftSection={<LuMonitor size={16} aria-hidden="true" />}
            rightSection={colorScheme === "auto" ? <LuCheck size={16} aria-hidden="true" /> : null}
            onClick={clearColorScheme}
          >
            System
          </Menu.Item>
          <Menu.Item
            leftSection={<LuSun size={16} aria-hidden="true" />}
            rightSection={colorScheme === "light" ? <LuCheck size={16} aria-hidden="true" /> : null}
            onClick={() => setColorScheme("light")}
          >
            Light
          </Menu.Item>
          <Menu.Item
            leftSection={<LuMoon size={16} aria-hidden="true" />}
            rightSection={colorScheme === "dark" ? <LuCheck size={16} aria-hidden="true" /> : null}
            onClick={() => setColorScheme("dark")}
          >
            Dark
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>
    </nav>
  );
};

export default TopBar;
