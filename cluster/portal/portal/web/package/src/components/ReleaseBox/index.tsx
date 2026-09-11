import { useQuery } from "@tanstack/react-query";
import { BsGithub } from "react-icons/bs";

interface GithubRelease {
  tag_name: string;
  name: string | null;
  html_url: string;
  published_at: string | null;
}

const REPO = "octelium/octelium";

const fetchLatestRelease = async (): Promise<GithubRelease> => {
  const res = await fetch(
    `https://api.github.com/repos/${REPO}/releases/latest`,
    {
      headers: { Accept: "application/vnd.github+json" },
    },
  );

  if (!res.ok) {
    throw new Error(`GitHub API responded with ${res.status}`);
  }

  return res.json();
};

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

export const ReleaseBox = () => {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["octelium-latest-release"],
    queryFn: fetchLatestRelease,
    staleTime: 1000 * 60 * 60,
    gcTime: 1000 * 60 * 60 * 24,
    retry: 1,
    refetchOnWindowFocus: false,
  });

  if (isError) {
    return null;
  }

  if (isLoading) {
    return (
      <div className="w-full rounded-xl border border-line p-3">
        <div className="h-3 w-20 rounded bg-surface-active animate-pulse" />
        <div className="mt-2 h-4 w-16 rounded bg-surface-active animate-pulse" />
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const date = formatDate(data.published_at);

  return (
    <a
      href={data.html_url}
      target="_blank"
      className="block w-full rounded-xl border border-line p-3 transition-colors duration-500 hover:border-line-strong hover:bg-surface-muted"
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">
          Latest release
        </span>
        <BsGithub className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
      </div>
      <div className="mt-1 text-sm font-bold text-fg">
        {data.tag_name}
      </div>
      {date && <div className="text-xs text-fg-subtle">Released {date}</div>}
    </a>
  );
};

export default ReleaseBox;
