import CopyText from "@/components/CopyText";
import InfoItem from "@/components/InfoItem";
import Loading from "@/components/Loading";
import Meta from "@/components/Meta";
import PageHeader from "@/components/PageHeader";
import { setItemsPerPage } from "@/features/settings/slice";
import { useAppDispatch, useAppSelector } from "@/utils/hooks";
import {
  DEFAULT_ITEMS_PER_PAGE,
  ITEMS_PER_PAGE_OPTIONS,
  isValidItemsPerPage,
} from "@/utils/preferences";
import {
  SegmentedControl,
  useMantineColorScheme,
  type MantineColorScheme,
} from "@mantine/core";
import { Monitor, Moon, Sun, UserRound } from "lucide-react";
import type { ReactNode } from "react";

const THEME_OPTIONS = [
  { value: "auto", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
];

const Section = (props: {
  title: string;
  description?: string;
  children: ReactNode;
}) => (
  <section className="rounded-xl border border-line bg-surface p-5 shadow-xs">
    <h2 className="text-base font-bold tracking-tight text-fg">
      {props.title}
    </h2>
    {props.description && (
      <p className="mt-1 text-sm font-medium text-fg-subtle">
        {props.description}
      </p>
    )}
    <div className="mt-4">{props.children}</div>
  </section>
);

const Settings = () => {
  const dispatch = useAppDispatch();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const status = useAppSelector((state) => state.settings.status);
  const itemsPerPage = useAppSelector(
    (state) => state.settings.itemsPerPage ?? DEFAULT_ITEMS_PER_PAGE,
  );

  if (!status) {
    return (
      <>
        <Meta title="Settings" />
        <Loading />
      </>
    );
  }

  const user = status.user;
  const name = user?.metadata?.name;
  const displayName = user?.metadata?.displayName;
  const email = user?.spec?.email;
  const picURL = user?.metadata?.picURL ?? status.session?.metadata?.picURL;

  return (
    <div className="pb-10">
      <Meta title="Settings" />

      <PageHeader
        title="Settings"
        description="Your account details and portal preferences."
      />

      <div className="flex flex-col gap-5">
        <Section title="Account">
          <div className="flex items-center gap-4">
            <div className="h-16 w-16 flex-none overflow-hidden rounded-full border border-line bg-surface-strong text-fg-faint">
              {picURL ? (
                <img
                  className="h-full w-full object-cover"
                  src={picURL}
                  alt={displayName || name || "User"}
                />
              ) : (
                <div className="flex h-full w-full items-center justify-center">
                  <UserRound size={26} aria-hidden />
                </div>
              )}
            </div>

            <div className="min-w-0 flex-1">
              <h3 className="truncate text-lg font-extrabold tracking-tight text-fg">
                {displayName || name || "Unknown User"}
              </h3>
              {displayName && name && displayName !== name && (
                <p className="mt-0.5 truncate text-sm font-semibold text-fg-subtle">
                  {name}
                </p>
              )}
            </div>
          </div>

          <dl className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <InfoItem title="Email">
              {email ? (
                <span className="flex items-center">
                  <CopyText value={email} />
                </span>
              ) : (
                <span className="text-fg-faint">Not set</span>
              )}
            </InfoItem>

            <InfoItem title="Cluster">
              {status.domain || <span className="text-fg-faint">Unknown</span>}
            </InfoItem>
          </dl>
        </Section>

        <Section
          title="Appearance"
          description="System follows your device preference. Choosing Light or Dark overrides it on this browser."
        >
          <SegmentedControl
            aria-label="Appearance"
            className="max-w-md"
            fullWidth
            size="sm"
            radius="md"
            value={colorScheme}
            onChange={(value) => setColorScheme(value as MantineColorScheme)}
            data={THEME_OPTIONS.map(({ value, label, icon: Icon }) => ({
              value,
              label: (
                <span className="flex items-center justify-center gap-1.5 font-bold">
                  <Icon size={14} aria-hidden />
                  {label}
                </span>
              ),
            }))}
          />
        </Section>

        <Section
          title="Items per page"
          description="Applies to Services and Namespaces lists on this browser."
        >
          <SegmentedControl
            aria-label="Items per page"
            className="max-w-md"
            fullWidth
            size="sm"
            radius="md"
            value={String(itemsPerPage)}
            onChange={(value) => {
              const next = Number(value);
              if (isValidItemsPerPage(next)) {
                dispatch(setItemsPerPage({ itemsPerPage: next }));
              }
            }}
            data={ITEMS_PER_PAGE_OPTIONS.map((option) => ({
              value: String(option),
              label: <span className="font-bold">{option}</span>,
            }))}
          />
        </Section>
      </div>
    </div>
  );
};

export default Settings;
