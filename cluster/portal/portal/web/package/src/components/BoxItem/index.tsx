const BoxItem = (props: { children?: React.ReactNode }) => {
  return (
    <div className="w-full my-8 border-[1px] border-line-strong rounded-lg p-2 shadow-sm">
      {props.children}
    </div>
  );
};

export default BoxItem;
