import type React from "react";

declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      "iron-remote-desktop": React.DetailedHTMLProps<
        React.HTMLAttributes<HTMLElement> & {
          scale?: "fit" | "real" | "full";
          verbose?: "true" | "false";
          debugwasm?: "OFF" | "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE";
          flexcentre?: "true" | "false";
          module?: unknown;
        },
        HTMLElement
      >;
    }
  }
}

export {};
