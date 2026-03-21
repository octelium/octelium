import LogoMain from "@/components/LogoMain";
import { getDomain } from "@/utils";

const Page = () => {
  return (
    <div>
      <title>Unauthorized Page - Octelium</title>
      <div className="flex items-center justify-center mt-4 mb-3">
        <LogoMain />
      </div>

      <div
        className="font-bold text-xl mb-4 text-zinc-900 text-center mt-16"
        style={{
          textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
        }}
      >
        <span>You are not authorized to access this resource</span>
      </div>
      <div className="font-bold text-sm my-4 text-zinc-500 text-center">
        <span>
          Visit Octelium Portal{" "}
          <a
            className="text-zinc-800 hover:text-black transition-all duration-500"
            href={`https://portal.${getDomain()}`}
          >
            here
          </a>{" "}
        </span>
      </div>
    </div>
  );
};

export default Page;
