import React from "react";

import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

dayjs.extend(relativeTime);

const TimeAgo = (props: { rfc3339?: string }) => {
  const [, setTick] = React.useState(0);
  React.useEffect(() => {
    if (!props.rfc3339) return;

    const interval = setInterval(
      () => setTick((value) => value + 1),
      10000,
    );
    return () => {
      clearInterval(interval);
    };
  }, [props.rfc3339]);
  if (!props.rfc3339) return null;
  return <React.Fragment>{dayjs(props.rfc3339).fromNow()}</React.Fragment>;
};

export default TimeAgo;
