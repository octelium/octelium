import { twMerge } from "tailwind-merge";

import LogoMain from "@/components/LogoMain";

const AuthPage = (props: {
  title: string;
  description?: React.ReactNode;
  compact?: boolean;
  wide?: boolean;
  children?: React.ReactNode;
}) => (
  <main className="flex flex-1 items-center justify-center px-2 py-4">
    <div className={twMerge("w-full max-w-[22rem]", props.wide && "max-w-lg")}>
      <header
        className={twMerge(
          "mb-10 flex flex-col items-center text-center",
          props.compact && "mb-7",
        )}
      >
        <LogoMain compact={props.compact} />
        <h1 className="text-2xl font-bold tracking-[-0.01em] text-balance text-fg">
          {props.title}
        </h1>
        {props.description && (
          <p className="mt-2 text-sm leading-6 text-fg-muted">
            {props.description}
          </p>
        )}
      </header>

      {props.children}
    </div>
  </main>
);

export default AuthPage;
