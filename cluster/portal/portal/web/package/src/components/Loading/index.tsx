import ClipLoader from "react-spinners/ClipLoader";

const Loading = () => {
  return (
    <div>
      <div className="min-h-[400px]">
        <ClipLoader
          color={"#111"}
          loading={true}
          size={150}
          aria-label="Loading Spinner"
          data-testid="loader"
        />
      </div>
    </div>
  );
};

export default Loading;
