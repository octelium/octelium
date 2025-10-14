import React from "react";

import { Timestamp } from "@/apis/google/protobuf/timestamp";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(utc);

import { Tooltip } from "@mantine/core";

const TimeAgo = (props: { rfc3339?: Timestamp }) => {
  if (!props.rfc3339) {
    return <></>;
  }

  const t = Timestamp.toDate(props.rfc3339);
  let [time, setTime] = React.useState(dayjs(t).fromNow());

  React.useEffect(() => {
    setTime(dayjs(t).fromNow());

    const interval = setInterval(() => setTime(dayjs(t).fromNow()), 10000);
    return () => {
      clearInterval(interval);
    };
  }, [props.rfc3339]);
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
