export default (props: { children?: React.ReactNode }) => {
  return (
    <div className="w-full my-8 border-[1px] border-gray-300 rounded-lg p-2 shadow-sm">
      {props.children}
    </div>
  );
};
