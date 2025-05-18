import * as isLeapYear from "dayjs/plugin/isLeapYear";

import React from "react";

import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

dayjs.extend(relativeTime);

const TimeAgo = (props: { rfc3339?: string }) => {
  if (!props.rfc3339 || props.rfc3339.length === 0) {
    return <React.Fragment></React.Fragment>;
  }
  let [time, setTime] = React.useState(dayjs(props.rfc3339).fromNow());
  React.useEffect(() => {
    setTime(dayjs(props.rfc3339).fromNow());

    const interval = setInterval(
      () => setTime(dayjs(props.rfc3339).fromNow()),
      10000
    );
    return () => {
      clearInterval(interval);
    };
  }, [props.rfc3339]);
  return <React.Fragment>{time}</React.Fragment>;
};

export default TimeAgo;
