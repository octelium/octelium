import ActionButton from "@/components/ActionButton";
import AuthPage from "@/components/AuthPage";
import { getPortalURL } from "@/utils";
import { LuHouse } from "react-icons/lu";

const Page = () => {
  return (
    <>
      <title>Unauthorized Page - Octelium</title>
      <AuthPage
        title="Access denied"
        description="You are not authorized to access this resource."
      >
        <ActionButton
          label="Go to the Octelium Portal"
          Icon={LuHouse}
          primary
          href={getPortalURL()}
        />
      </AuthPage>
    </>
  );
};

export default Page;
