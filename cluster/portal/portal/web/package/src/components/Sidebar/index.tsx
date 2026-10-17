import { twMerge } from "@/lib/utils";
import { getPortalURL } from "@/utils";
import { useAppSelector } from "@/utils/hooks";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  BookOpen,
  Boxes,
  LayoutGrid,
  LockKeyhole,
  LogOut,
  PanelTop,
  Settings,
  Tag,
  X,
} from "lucide-react";
import * as React from "react";
import { LuGithub } from "react-icons/lu";
import { NavLink } from "react-router-dom";

type NavIcon = React.ComponentType<{
  size?: number;
  strokeWidth?: number;
  className?: string;
  "aria-hidden"?: boolean;
}>;

type NavItem = {
  to: string;
  label: string;
  icon: NavIcon;
};

const NAV_ITEMS: NavItem[] = [
  { to: "/services", label: "Services", icon: PanelTop },
  { to: "/namespaces", label: "Namespaces", icon: Boxes },
  { to: "/settings", label: "Settings", icon: Settings },
];

const REPO = "octelium/octelium";

const rowClass =
  "flex min-h-9 items-center gap-2.5 rounded-lg px-2.5 text-body outline-none transition-[background-color,color,box-shadow] duration-150 focus-visible:ring-2 focus-visible:ring-slate-400 [@media(pointer:coarse)]:min-h-11";

const NavigationLink = (props: { item: NavItem; onNavigate?: () => void }) => (
  <NavLink
    to={props.item.to}
    onClick={props.onNavigate}
    className={({ isActive }) =>
      twMerge(
        rowClass,
        isActive
          ? "bg-white font-semibold text-slate-900 shadow-card ring-1 ring-slate-200"
          : "font-normal text-slate-600 hover:bg-slate-200/50 hover:text-slate-900",
      )
    }
  >
    {({ isActive }) => (
      <>
        <props.item.icon
          size={16}
          strokeWidth={isActive ? 2.25 : 1.75}
          className="shrink-0"
          aria-hidden
        />
        <span className="truncate">{props.item.label}</span>
      </>
    )}
  </NavLink>
);

const ExternalLink = (props: {
  href: string;
  label: string;
  icon: NavIcon;
  description?: React.ReactNode;
}) => (
  <a
    href={props.href}
    target="_blank"
    className={twMerge(
      rowClass,
      "group font-normal text-slate-600 hover:bg-slate-200/50 hover:text-slate-900",
      props.description && "items-start py-2",
    )}
  >
    <props.icon
      size={16}
      strokeWidth={1.75}
      className={twMerge("shrink-0", props.description && "mt-0.5")}
      aria-hidden
    />
    <span className="min-w-0 flex-1">
      <span className="block truncate">{props.label}</span>
      {props.description}
    </span>
    <ArrowUpRight
      size={13}
      className={twMerge(
        "shrink-0 text-slate-400 transition-colors group-hover:text-slate-600",
        props.description && "mt-1",
      )}
      aria-hidden
    />
  </a>
);

interface GithubRelease {
  tag_name: string;
  html_url: string;
  published_at: string | null;
}

const formatDate = (iso: string | null): string | null => {
  if (!iso) {
    return null;
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return null;
  }
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
};

const LatestRelease = () => {
  const { data } = useQuery({
    queryKey: ["octelium-latest-release"],
    queryFn: async ({ signal }): Promise<GithubRelease> => {
      const res = await fetch(
        `https://api.github.com/repos/${REPO}/releases/latest`,
        { headers: { Accept: "application/vnd.github+json" }, signal },
      );
      if (!res.ok) {
        throw new Error(`GitHub API responded with ${res.status}`);
      }
      return res.json();
    },
    staleTime: 1000 * 60 * 60,
    gcTime: 1000 * 60 * 60 * 24,
    retry: 1,
    refetchOnWindowFocus: false,
  });

  const date = formatDate(data?.published_at ?? null);

  return (
    <ExternalLink
      href={data?.html_url ?? `https://github.com/${REPO}/releases`}
      label="Releases"
      icon={Tag}
      description={
        data?.tag_name ? (
          <span className="mt-0.5 flex min-w-0 items-center gap-1.5 text-micro font-normal text-slate-500">
            <span className="truncate font-mono font-medium text-slate-700">
              {data.tag_name}
            </span>
            {date && (
              <>
                <span aria-hidden className="text-slate-300">
                  ·
                </span>
                <span className="sr-only">released</span>
                <time
                  dateTime={data.published_at ?? undefined}
                  className="shrink-0"
                >
                  {date}
                </time>
              </>
            )}
          </span>
        ) : undefined
      }
    />
  );
};

const Sidebar = (props: {
  onNavigate?: () => void;
  onClose?: () => void;
  onSignOut: () => void;
}) => {
  const status = useAppSelector((state) => state.settings.status);
  const cluster =
    status?.cluster?.metadata?.displayName || status?.domain || undefined;

  return (
    <div className="flex h-full min-h-0 w-full flex-col">
      <div className="flex h-16 shrink-0 items-center gap-2.5 px-4">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-700 shadow-card">
          <LayoutGrid size={16} strokeWidth={1.8} aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-body font-semibold leading-tight text-slate-800">
            Portal
          </p>
          {cluster && (
            <p
              className="truncate text-micro font-normal text-slate-500"
              title={cluster}
            >
              {cluster}
            </p>
          )}
        </div>
        {props.onClose && (
          <button
            type="button"
            aria-label="Close navigation"
            onClick={props.onClose}
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-slate-500 outline-none transition-colors hover:bg-slate-200/60 hover:text-slate-900 focus-visible:ring-2 focus-visible:ring-slate-400"
          >
            <X size={17} aria-hidden />
          </button>
        )}
      </div>

      <nav
        aria-label="Portal"
        className="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto overscroll-contain px-2 pb-4 pt-2 [scrollbar-width:thin]"
      >
        <div className="flex flex-col gap-1">
          {NAV_ITEMS.map((item) => (
            <NavigationLink
              key={item.to}
              item={item}
              onNavigate={props.onNavigate}
            />
          ))}
        </div>

        <div className="flex flex-col gap-1">
          <span className="mb-1 px-2.5 text-xs font-medium text-slate-500">
            Resources
          </span>
          <ExternalLink
            href="https://octelium.com/docs"
            label="Documentation"
            icon={BookOpen}
          />
          <ExternalLink
            href={`https://github.com/${REPO}`}
            label="GitHub"
            icon={LuGithub}
          />
          <LatestRelease />
        </div>
      </nav>

      <div className="flex shrink-0 flex-col gap-1 border-t border-slate-200/80 p-2">
        <a
          href={getPortalURL("/authenticators")}
          className={twMerge(
            rowClass,
            "group font-normal text-slate-600 hover:bg-slate-200/50 hover:text-slate-900",
          )}
        >
          <LockKeyhole
            size={16}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden
          />
          <span className="min-w-0 flex-1 truncate">Authenticators</span>
          <ArrowUpRight
            size={13}
            className="shrink-0 text-slate-400 transition-colors group-hover:text-slate-600"
            aria-hidden
          />
        </a>
        <button
          type="button"
          onClick={props.onSignOut}
          className={twMerge(
            rowClass,
            "w-full text-left font-normal text-slate-600 hover:bg-red-50 hover:text-red-700",
          )}
        >
          <LogOut
            size={16}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden
          />
          <span className="min-w-0 flex-1 truncate">Sign out</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
