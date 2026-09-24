import LogoMain from "@/components/LogoMain";
import { getPortalURL } from "@/utils";

const Page = () => {
  return (
    <div>
      <title>Unauthorized Page - Octelium</title>
      <div className="flex items-center justify-center mt-4 mb-3">
        <LogoMain />
      </div>

      <div
        className="font-bold text-xl mb-4 text-fg text-center mt-16"
        style={{
          textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
        }}
      >
        <span>You are not authorized to access this resource</span>
      </div>
      <div className="font-bold text-sm my-4 text-fg-subtle text-center">
        <span>
          Visit Octelium Portal{" "}
          <a
            className="text-fg-muted hover:text-fg transition-all duration-500"
            href={getPortalURL()}
          >
            here
          </a>{" "}
        </span>
      </div>
    </div>
  );
};

export default Page;
