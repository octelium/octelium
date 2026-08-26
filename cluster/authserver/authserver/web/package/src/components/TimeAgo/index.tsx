import React from "react";

import { Timestamp } from "@octelium/apis/google/protobuf/timestamp";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(utc);

import { Tooltip } from "@mantine/core";

const TimeAgo = (props: { rfc3339?: Timestamp }) => {
  const [, setTick] = React.useState(0);

  React.useEffect(() => {
    if (!props.rfc3339) {
      return;
    }

    const interval = setInterval(() => setTick((value) => value + 1), 10000);
    return () => {
      clearInterval(interval);
    };
  }, [props.rfc3339]);

  if (!props.rfc3339) {
    return <></>;
  }

  const t = Timestamp.toDate(props.rfc3339);
  const time = dayjs(t).fromNow();
  return (
    <Tooltip
      label={
        <p className="font-bold shadow-md text-xs rounded-sm">
          {dayjs(t).local().format("hh:mm:ss A, ddd MMM D, YYYY")}
        </p>
      }
      transitionProps={{
        transition: "fade",
        duration: 340,
      }}
    >
      <span>{time}</span>
    </Tooltip>
  );
};

export default TimeAgo;
