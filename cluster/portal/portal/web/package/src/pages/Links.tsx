import { BsGithub } from "react-icons/bs";
import { IoBook } from "react-icons/io5";

const LinkItem = (props: { link: string; children?: React.ReactNode }) => {
  return (
    <div>
      <a
        href={props.link}
        target="_blank"
        className="mb-2 w-full transition-all duration-300 text-zinc-200 hover:text-white inline-flex items-center text-sm leading-none"
      >
        {props.children}
      </a>
    </div>
  );
};

export default () => {
  return (
    <div className="flex flex-col my-4 font-bold bg-zinc-800 border-none rounded-lg p-3 shadow-lg m-2">
      <LinkItem link="https://github.com/octelium/octelium">
        <BsGithub />
        <span className="ml-2">GitHub Repository</span>
      </LinkItem>

      <LinkItem link="https://octelium.com/docs">
        <IoBook />
        <span className="ml-2">Octelium Docs</span>
      </LinkItem>
    </div>
  );
};
