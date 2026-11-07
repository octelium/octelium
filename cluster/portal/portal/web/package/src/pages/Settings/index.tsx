import { setItemsPerPage } from "@/features/settings/slice";
import {
  Avatar,
  DetailList,
  DetailRow,
  DetailValue,
  DocumentTitle,
  ErrorState,
  PageHeader,
  SectionCard,
  SettingRow,
} from "@/ui";
import { getDomain, getPortalURL } from "@/utils";
import { getClientUser } from "@/utils/client";
import { useAppDispatch, useAppSelector } from "@/utils/hooks";
import {
  DEFAULT_ITEMS_PER_PAGE,
  ITEMS_PER_PAGE_OPTIONS,
  isValidItemsPerPage,
} from "@/utils/preferences";
import { COLOR_SCHEMES } from "@/utils/theme/colorScheme";
import {
  Button,
  SegmentedControl,
  useMantineColorScheme,
  type MantineColorScheme,
} from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import {
  ExternalLink,
  LockKeyhole,
  SlidersHorizontal,
  UserRound,
} from "lucide-react";

const Identity = () => {
  const statusQuery = useQuery({
    queryKey: ["user/getStatus"],
    queryFn: async () => {
      const { response } = await getClientUser().getStatus({});
      return response;
    },
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
  });

  if (statusQuery.isPending) {
    return (
      <SectionCard
        title="Account"
        icon={<UserRound size={14} strokeWidth={2.25} />}
      >
        <div
          role="status"
          aria-label="Loading your account"
          className="flex items-center gap-3"
        >
          <div className="h-12 w-12 rounded-full bg-slate-100 motion-safe:animate-pulse" />
          <div className="flex-1 space-y-2">
            <div className="h-3 w-1/3 rounded bg-slate-100 motion-safe:animate-pulse" />
            <div className="h-2.5 w-1/2 rounded bg-slate-50 motion-safe:animate-pulse" />
          </div>
        </div>
      </SectionCard>
    );
  }

  if (!statusQuery.data) {
    return (
      <ErrorState
        title="Could not load your account"
        error={statusQuery.error}
        onRetry={() => statusQuery.refetch()}
      />
    );
  }

  const user = statusQuery.data.user;
  const name = user?.metadata?.name;
  const displayName = user?.metadata?.displayName || name || "Unknown user";
  const email = user?.spec?.email;
  const picURL =
    statusQuery.data.session?.metadata?.picURL || user?.metadata?.picURL;

  return (
    <SectionCard
      title="Account"
      description="The identity you are signed in with"
      icon={<UserRound size={14} strokeWidth={2.25} />}
      bodyClassName="p-0"
    >
      <div className="flex min-w-0 items-center gap-3 border-b border-slate-100 p-4">
        <Avatar src={picURL} name={displayName} size="lg" />
        <p className="min-w-0 truncate text-base font-semibold text-slate-900">
          {displayName}
        </p>
      </div>
      <DetailList className="rounded-none rounded-b-[11px] border-0 shadow-none">
        {name && (
          <DetailRow label="Username">
            <DetailValue value={name} copyLabel="Copy username" />
          </DetailRow>
        )}
        {email && (
          <DetailRow label="Email">
            <DetailValue value={email} copyLabel="Copy email" />
          </DetailRow>
        )}
        <DetailRow label="Cluster domain">
          <DetailValue
            value={statusQuery.data.domain || getDomain()}
            copyLabel="Copy Cluster domain"
          />
        </DetailRow>
      </DetailList>
    </SectionCard>
  );
};

const Settings = () => {
  const dispatch = useAppDispatch();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const itemsPerPage = useAppSelector(
    (state) => state.settings.itemsPerPage ?? DEFAULT_ITEMS_PER_PAGE,
  );

  return (
    <div className="w-full">
      <DocumentTitle title="Settings" />
      <PageHeader
        title="Settings"
        description="Your account in this Cluster and how the portal works on this device."
      />

      <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
        <Identity />

        <div className="flex min-w-0 flex-col gap-4">
          <SectionCard
            title="Preferences"
            description="Saved in this browser only"
            icon={<SlidersHorizontal size={14} strokeWidth={2.25} />}
            bodyClassName="divide-y divide-slate-100 p-0"
          >
            <SettingRow
              title="Color scheme"
              description="System follows your device"
            >
              <SegmentedControl
                aria-label="Color scheme"
                value={colorScheme}
                onChange={(value) =>
                  setColorScheme(value as MantineColorScheme)
                }
                data={COLOR_SCHEMES}
                size="xs"
                className="w-full @md:w-56"
              />
            </SettingRow>
            <SettingRow
              title="Items per page"
              description="For the Services and Namespaces lists"
            >
              <SegmentedControl
                aria-label="Items per page"
                value={String(itemsPerPage)}
                onChange={(value) => {
                  const next = Number(value);
                  if (isValidItemsPerPage(next)) {
                    dispatch(setItemsPerPage({ itemsPerPage: next }));
                  }
                }}
                data={ITEMS_PER_PAGE_OPTIONS.map(String)}
                size="xs"
                className="w-full @md:w-56"
              />
            </SettingRow>
          </SectionCard>

          <SectionCard
            title="Security"
            icon={<LockKeyhole size={14} strokeWidth={2.25} />}
            bodyClassName="p-0"
          >
            <SettingRow
              title="Authenticators"
              description="Passkeys and other ways you sign in"
            >
              <Button
                component="a"
                href={getPortalURL("/authenticators")}
                variant="default"
                size="xs"
                className="w-full @md:w-auto"
                rightSection={<ExternalLink size={12} strokeWidth={2.25} />}
              >
                Manage authenticators
              </Button>
            </SettingRow>
          </SectionCard>
        </div>
      </div>
    </div>
  );
};

export default Settings;
