import { setItemsPerPage } from "@/features/settings/slice";
import {
  Avatar,
  CopyValue,
  DocumentTitle,
  ErrorState,
  Field,
  InfoGrid,
  KeyValue,
  Note,
  PageHeader,
  SectionCard,
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
import { GetStatusResponse_User_Spec_Type } from "@octelium/apis/main/userv1";
import { useQuery } from "@tanstack/react-query";
import {
  ExternalLink,
  LockKeyhole,
  Rows3,
  SunMoon,
  UserRound,
} from "lucide-react";

const USER_TYPES: Partial<Record<GetStatusResponse_User_Spec_Type, string>> = {
  [GetStatusResponse_User_Spec_Type.HUMAN]: "Human",
  [GetStatusResponse_User_Spec_Type.WORKLOAD]: "Workload",
};

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
        title="Signed-in user"
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
  const userType = USER_TYPES[user?.spec?.type ?? 0];
  const picURL =
    statusQuery.data.session?.metadata?.picURL || user?.metadata?.picURL;

  return (
    <SectionCard
      title="Signed-in user"
      description="The identity you are signed in to this Cluster with"
      icon={<UserRound size={14} strokeWidth={2.25} />}
    >
      <div className="flex flex-col gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <Avatar src={picURL} name={displayName} size="lg" />
          <div className="min-w-0">
            <p className="truncate text-base font-semibold text-slate-900">
              {displayName}
            </p>
            {email && (
              <p className="truncate text-xs font-normal text-slate-500">
                {email}
              </p>
            )}
          </div>
        </div>

        <InfoGrid className="border-t border-slate-100 pt-4">
          {name && (
            <KeyValue label="Username">
              <CopyValue value={name} copyLabel="Copy username" />
            </KeyValue>
          )}
          <KeyValue label="Cluster domain">
            {statusQuery.data.domain || getDomain()}
          </KeyValue>
          {email && (
            <KeyValue label="Email">
              <CopyValue value={email} copyLabel="Copy email" mono={false} />
            </KeyValue>
          )}
          {userType && <KeyValue label="Account type">{userType}</KeyValue>}
        </InfoGrid>
      </div>
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
    <div className="w-full max-w-3xl">
      <DocumentTitle title="Settings" />
      <PageHeader
        title="Settings"
        description="Your account in this Cluster and how the portal looks on this device."
      />

      <div className="flex flex-col gap-4">
        <Identity />

        <SectionCard
          title="Authentication"
          description="Passkeys and other authenticators for your account"
          icon={<LockKeyhole size={14} strokeWidth={2.25} />}
        >
          <div className="flex flex-col gap-3">
            <Note>
              Authenticators are managed on a dedicated page. Changes apply to
              every application you sign in to with this account.
            </Note>
            <Button
              component="a"
              href={getPortalURL("/authenticators")}
              variant="default"
              className="self-start"
              leftSection={<LockKeyhole size={14} strokeWidth={2.25} />}
              rightSection={<ExternalLink size={12} strokeWidth={2.25} />}
            >
              Manage authenticators
            </Button>
          </div>
        </SectionCard>

        <SectionCard
          title="Appearance"
          description="How this portal looks on this device"
          icon={<SunMoon size={14} strokeWidth={2.25} />}
        >
          <Field
            label="Color scheme"
            description="System follows the color scheme of your operating system. The choice is kept in this browser only."
          >
            <SegmentedControl
              aria-label="Color scheme"
              value={colorScheme}
              onChange={(value) => setColorScheme(value as MantineColorScheme)}
              data={COLOR_SCHEMES}
              size="sm"
              className="w-full max-w-xs"
            />
          </Field>
        </SectionCard>

        <SectionCard
          title="Lists"
          description="How the Services and Namespaces lists are paginated"
          icon={<Rows3 size={14} strokeWidth={2.25} />}
        >
          <Field
            label="Items per page"
            description="The number of Services or Namespaces shown on each page. The choice is kept in this browser only."
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
              size="sm"
              className="w-full max-w-xs"
            />
          </Field>
        </SectionCard>
      </div>
    </div>
  );
};

export default Settings;
