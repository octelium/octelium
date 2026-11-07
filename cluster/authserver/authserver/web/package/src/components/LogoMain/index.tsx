import { twMerge } from "tailwind-merge";

import Logo from "@/assets/logo.svg?react";

const LogoMain = (props: { compact?: boolean }) => (
  <Logo
    aria-hidden="true"
    focusable="false"
    className={twMerge(
      "mb-7 size-[clamp(6.5rem,18.5svh,10.5rem)] rounded-full shadow-logo [&>path:first-child]:fill-(--portal-logo-disc)",
      props.compact && "mb-5 size-20",
    )}
  />
);

export default LogoMain;
