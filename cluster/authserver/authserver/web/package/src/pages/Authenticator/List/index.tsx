import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ListAvailableAuthenticators, WithAuthenticators } from "../Authenticate";

const Page = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  const [query] = useState(() => new URLSearchParams(searchParams));

  useEffect(() => {
    if (searchParams.toString()) {
      setSearchParams(new URLSearchParams(), { replace: true });
    }
  }, [searchParams, setSearchParams]);

  return (
    <>
      <title>Authenticators - Octelium</title>
      <WithAuthenticators>
        {(data) => <ListAvailableAuthenticators resp={data} query={query} />}
      </WithAuthenticators>
    </>
  );
};

export default Page;
