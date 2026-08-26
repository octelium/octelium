import { Loader } from "@mantine/core";

const Loading = () => {
  return (
    <div className="flex min-h-[320px] items-center justify-center" role="status" aria-label="Loading">
      <Loader color="dark" size="md" aria-label="Loading Spinner" />
    </div>
  );
};

export default Loading;
