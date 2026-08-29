const escapeRegExp = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const HighlightText = (props: { text: string; tokens?: string[] }) => {
  const tokens = (props.tokens ?? []).filter(Boolean);

  if (tokens.length === 0) {
    return <>{props.text}</>;
  }

  const pattern = tokens
    .slice()
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp)
    .join("|");

  const parts = props.text.split(new RegExp(`(${pattern})`, "ig"));

  return (
    <>
      {parts.map((part, index) =>
        index % 2 === 1 ? (
          <mark
            key={index}
            className="rounded-[3px] bg-amber-200/70 px-px text-inherit"
          >
            {part}
          </mark>
        ) : (
          part
        ),
      )}
    </>
  );
};

export default HighlightText;
